// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.ArrayList;
import java.util.List;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.http.internal.LogSafe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Request-scoped carrier of what one request has seen: the blocking Java binding of a receiver's result, for servlet
 * and other thread-per-request code, virtual threads included. The receivers decide; the request's filter enters
 * their result here ({@link #enter(Accepted)}), which stores the chain a service received and the influence that came
 * with it; the handler adds the influence of whatever else it reads, and labels what it produces; the outbound
 * interceptor reads the chain to append the next stamp and commits the influence so far. It is not the protocol: a
 * reactive or non-Java binding carries the same values its own way, around the same receiver functions.
 *
 * <p>Calls are synchronous on the request thread, so a thread-local is sufficient. Threads are pooled, so what one
 * unit of work learns must not outlive it: influence left behind would be committed to another request's calls,
 * and a label to another request's response. The context is therefore carried only inside a {@link Scope}. Each of
 * the two filters enters one per request; outside any scope the outbound interceptor neither reads the context nor
 * records responses into it, so calls made there stamp with no influence and leave nothing behind.
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
     * Marks the inbound chain as having passed the live order at this hop. Only {@link #enter} calls this, from a
     * receiver's result, which no other code can make, so that anything which later signs on the strength of it (the
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
     * Opens a scope on this thread, starting from an empty context; closing it empties the context again. The
     * inbound filter opens one around every request it serves. Background work (a scheduled job, a startup
     * runner) that wants what its calls learn to be carried opens its own, with try-with-resources, around one
     * unit of work. Scopes do not nest: opening one while one is open throws {@link IllegalStateException}, since
     * the inner scope would otherwise drop the outer one's influence when it closed.
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
     * Opens the scope a request the receiver served is handled in, holding what it decided: the chain the request
     * carried, the influence the handler starts from, and the chain as verified at this hop only where it was. A scope
     * that other code left open on this pooled thread and never closed is ended first, with a warning: refusing to
     * open the request's own would fail this request and every later one served here.
     *
     * @throws IllegalArgumentException for a refusal, which is answered, not served
     */
    public static Scope enter(Accepted accepted) {
        if (accepted.refusal() != null) {
            throw new IllegalArgumentException("a refused request is not served");
        }
        Scope scope = openEnded();
        setInboundChain(accepted.inbound());
        if (accepted.verifiedChain() != null) {
            markVerified(accepted.verifiedChain());
        }
        addInfluence(accepted.influence().toArray(InfluenceEntry[]::new));
        return scope;
    }

    /**
     * {@link #enter(Accepted)} for a partner's call: in an attested session, the chain and influence that verified
     * there; in an unsafe one, nothing, whatever the request carried.
     *
     * @throws IllegalArgumentException for a refusal, which is answered, not served
     */
    public static Scope enter(PartnerAccepted accepted) {
        if (accepted.refusal() != null) {
            throw new IllegalArgumentException("a refused request is not served");
        }
        Scope scope = openEnded();
        if (accepted.attested()) {
            addInfluence(accepted.influence().toArray(InfluenceEntry[]::new));
            setInboundChain(accepted.verifiedChain());
            markVerified(accepted.verifiedChain());
        }
        return scope;
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
     * Ends whatever scope is open on this thread and empties the context. Only {@link #enter} calls this, when a
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
