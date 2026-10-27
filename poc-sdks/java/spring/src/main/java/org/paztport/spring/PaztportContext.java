// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.ArrayList;
import java.util.List;
import org.paztport.core.ContentLabel;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.StampV3;

/**
 * Request-scoped carrier of what one request has seen. The inbound filter stores the chain a service received and
 * the influence that came with it; the handler adds the influence of whatever else it reads, and labels what it
 * produces; the outbound interceptor reads the chain to append the next stamp and commits the influence so far.
 *
 * <p>Calls are synchronous on the request thread, so a thread-local is sufficient. Threads are pooled, so what one
 * unit of work learns must not outlive it: influence left behind would be committed to another request's calls,
 * and a label to another request's response. The context is therefore carried only inside a {@link Scope}. The
 * inbound filter opens one per request; outside any scope the outbound interceptor neither reads the context nor
 * records responses into it, so calls made there stamp with no influence and leave nothing behind.
 */
public final class PaztportContext {

    private static final ThreadLocal<List<StampV3>> INBOUND = new ThreadLocal<>();
    private static final ThreadLocal<List<InfluenceEntry>> INFLUENCE = ThreadLocal.withInitial(ArrayList::new);
    private static final ThreadLocal<List<ContentLabel>> LABELS = ThreadLocal.withInitial(ArrayList::new);
    private static final ThreadLocal<Boolean> OPEN = ThreadLocal.withInitial(() -> false);

    private PaztportContext() {
    }

    public static void setInboundChain(List<StampV3> chain) {
        INBOUND.set(chain);
    }

    /** The inbound chain for this request, or null if none was received or it did not parse (e.g. at the origin). */
    public static List<StampV3> inboundChain() {
        return INBOUND.get();
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
        if (OPEN.get()) {
            throw new IllegalStateException("a paztport context scope is already open on this thread");
        }
        clear();
        OPEN.set(true);
        return new Scope();
    }

    /** True while a scope is open on this thread: only then are responses recorded as influence. */
    public static boolean isOpen() {
        return OPEN.get();
    }

    /** An open scope; closing it empties the context and ends the scope. */
    public static final class Scope implements AutoCloseable {

        private Scope() {
        }

        @Override
        public void close() {
            clear();
            OPEN.remove();
        }
    }

    /** Empties the context; an open scope stays open. */
    public static void clear() {
        INBOUND.remove();
        INFLUENCE.remove();
        LABELS.remove();
    }
}
