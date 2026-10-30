// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.Peer;
import org.paztport.http.internal.LogSafe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The blocking Java binding of the receivers: a request-scoped carrier of what one request has seen, for servlet and
 * other thread-per-request code, virtual threads included. It is not the protocol. The receivers
 * ({@link HttpReceiver}, {@link PartnerReceiver}) decide each request without it; a framework's adapter runs them
 * through it ({@link #accept(HttpReceiver, InboundRequest, Peer, VerificationMode)}), which opens the request's scope
 * and stores the chain the service received and the influence that came with it; the handler adds the influence of
 * whatever else it reads, and labels what it produces; the caller reads the chain to append the next stamp and
 * commits the influence so far. A reactive binding, or another language's (Go would use {@code context.Context}),
 * carries the same values its own way around the same receiver functions.
 *
 * <p>Calls are synchronous on the request thread, so a thread-local is sufficient. Threads are pooled, so what one
 * unit of work learns must not outlive it: influence left behind would be committed to another request's calls,
 * and a label to another request's response. The context is therefore carried only inside a {@link Scope}. An
 * adapter opens one per request it filters, through {@link #accept}; outside any scope the caller neither reads the
 * context nor records responses into it, so calls made there stamp with no influence and leave nothing behind.
 *
 * <p>The verified chain is the one value here other code signs on the strength of (the egress's boundary stamp, the
 * trusted-record rule), so it is set only by {@link #accept}, from what the receiver it ran returned: the method that
 * sets it is package-private, beside the receivers, and an application can read the chain but never mark one.
 */
public final class RequestContext {

    private static final Logger LOG = LoggerFactory.getLogger(RequestContext.class);

    private static final ThreadLocal<List<StampV3>> INBOUND = new ThreadLocal<>();
    private static final ThreadLocal<List<StampV3>> VERIFIED = new ThreadLocal<>();
    private static final ThreadLocal<List<InfluenceEntry>> INFLUENCE = ThreadLocal.withInitial(ArrayList::new);
    private static final ThreadLocal<List<ContentLabel>> LABELS = ThreadLocal.withInitial(ArrayList::new);
    private static final ThreadLocal<Scope> CURRENT = new ThreadLocal<>();

    private RequestContext() {
    }

    public static void setInboundChain(List<StampV3> chain) {
        INBOUND.set(chain);
    }

    /** The inbound chain for this request, or null if none was received or it did not parse (e.g. at the origin). */
    public static List<StampV3> inboundChain() {
        return INBOUND.get();
    }

    /**
     * Marks the inbound chain as having passed the live order at this hop. Only {@link #accept} calls this, from the
     * result of the receiver it has just run, so that anything which later signs on the strength of it (the
     * boundary signer) can rely on it never being set by a chain that failed, was not checked, or came to an origin.
     */
    static void markVerified(List<StampV3> chain) {
        VERIFIED.set(chain);
    }

    /**
     * The request's inbound chain when it passed the live order at this hop, otherwise null: a chain that failed in
     * audit, a hop that is switched off, an origin, and a request outside any scope all give null.
     */
    public static List<StampV3> verifiedChain() {
        return VERIFIED.get();
    }

    /** Everything that has shaped this request so far, in the order it was added; a read-only copy. */
    public static List<InfluenceEntry> influence() {
        return List.copyOf(INFLUENCE.get());
    }

    /** Records content this request has read, so every call it makes from now on commits to it. */
    public static void addInfluence(InfluenceEntry... entries) {
        INFLUENCE.get().addAll(List.of(entries));
    }

    /**
     * Labels content this request produces, with a fresh content id. {@code owner} is null unless the content is
     * someone's private data.
     */
    public static void label(InfluenceClass cls, String owner) {
        LABELS.get().add(ContentLabel.fresh(cls, owner));
    }

    /** The labels added so far, in order; a read-only copy. */
    public static List<ContentLabel> labels() {
        return List.copyOf(LABELS.get());
    }

    /**
     * Opens a scope on this thread, starting from an empty context; closing it empties the context again. A request
     * is served in the one {@link #accept} opens. Background work (a scheduled job, a startup runner) that wants what
     * its calls learn to be carried opens its own, with try-with-resources, around one unit of work. Scopes do not
     * nest: opening one while one is open throws {@link IllegalStateException}, since the inner scope would otherwise
     * drop the outer one's influence when it closed.
     */
    public static Scope open() {
        if (CURRENT.get() != null) {
            throw new IllegalStateException("a paztport context scope is already open on this thread");
        }
        clear();
        Scope scope = new Scope();
        CURRENT.set(scope);
        return scope;
    }

    /**
     * The blocking binding of {@link HttpReceiver#accept}: ends a scope that other code left open on this pooled thread
     * and never closed, with a warning, opens the request's own, and only then runs the receiver in it, so whatever
     * the receiver calls out to (the listener, the event publisher) runs in the request's scope with the chain the
     * request carries already held, and a stale scope can outlive no request, refused or not. Refusing to open the
     * request's own scope instead would fail this request and every later one served here. Once the receiver has
     * decided, the scope holds, for a request it serves, the influence the handler starts from and the chain as
     * verified at this hop only where it was.
     *
     * <p>Close what this returns, with try-with-resources, once the request is answered, whatever the answer: the
     * scope ends then. If the receiver throws, the scope is ended before the exception goes on.
     */
    public static Entered<Accepted> accept(HttpReceiver receiver, InboundRequest request, Peer peer,
            VerificationMode mode) {
        return entered(() -> {
            Accepted accepted = receiver.accept(request, peer, mode, RequestContext::setInboundChain);
            if (accepted.refusal() == null) {
                if (accepted.verifiedChain() != null) {
                    markVerified(accepted.verifiedChain());
                }
                addInfluence(accepted.influence().toArray(InfluenceEntry[]::new));
            }
            return accepted;
        });
    }

    /**
     * {@link #accept(HttpReceiver, InboundRequest, Peer, VerificationMode)} for a partner's call: the scope is opened
     * first in the same way, and then holds, in an attested session, the chain and influence that verified there,
     * and in an unsafe one nothing, whatever the request carried.
     */
    public static Entered<PartnerAccepted> accept(PartnerReceiver receiver, InboundRequest request, PeerCert peer) {
        return entered(() -> {
            PartnerAccepted accepted = receiver.accept(request, peer);
            if (accepted.attested()) {
                addInfluence(accepted.influence().toArray(InfluenceEntry[]::new));
                setInboundChain(accepted.verifiedChain());
                markVerified(accepted.verifiedChain());
            }
            return accepted;
        });
    }

    /**
     * Opens the request's scope ({@link #openEnded}), then decides in it. Whatever {@code decide} throws ends the
     * scope first: a checked exception thrown where the compiler cannot see it, as some libraries do, as much as a
     * runtime exception or an error, since a scope left open would stay with the pooled thread.
     */
    private static <T> Entered<T> entered(Supplier<T> decide) {
        Scope scope = openEnded();
        try {
            return new Entered<>(scope, decide.get());
        } catch (Throwable t) {
            scope.close();
            throw t;
        }
    }

    /**
     * A request's scope, open, with what its receiver decided about it ({@link #result}): a refusal to answer, or what
     * the handler is served with. Closing it ends the scope, as closing a {@link Scope} does.
     */
    public static final class Entered<T> implements AutoCloseable {

        private final Scope scope;
        private final T result;

        private Entered(Scope scope, T result) {
            this.scope = scope;
            this.result = result;
        }

        /** What the receiver decided. */
        public T result() {
            return result;
        }

        @Override
        public void close() {
            scope.close();
        }
    }

    /** {@link #open}, after ending a scope leaked on this thread. */
    private static Scope openEnded() {
        if (isOpen()) {
            LOG.warn("a paztport context scope was leaked on thread {}; ending it before serving this request",
                    LogSafe.of(Thread.currentThread().getName()));
            reset();
        }
        return open();
    }

    /** True while a scope is open on this thread: only then are responses recorded as influence. */
    public static boolean isOpen() {
        return CURRENT.get() != null;
    }

    /**
     * Ends whatever scope is open on this thread and empties the context. Only {@link #accept} calls this, when a
     * scope that other code opened on a pooled thread was never closed: without it, every later request served on
     * that thread would fail to open its own.
     */
    static void reset() {
        clear();
        CURRENT.remove();
    }

    /**
     * An open scope; closing it empties the context and ends the scope. Closing a scope that has already ended, or
     * that was ended by {@link #reset}, does nothing, so a late or repeated close cannot end the scope that is
     * current now.
     */
    public static final class Scope implements AutoCloseable {

        private Scope() {
        }

        @Override
        public void close() {
            if (CURRENT.get() == this) {
                reset();
            }
        }
    }

    /** Empties the context; an open scope stays open. */
    public static void clear() {
        INBOUND.remove();
        VERIFIED.remove();
        INFLUENCE.remove();
        LABELS.remove();
    }
}
