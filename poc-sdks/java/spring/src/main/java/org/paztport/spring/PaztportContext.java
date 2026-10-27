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
 * <p>Calls are synchronous on the request thread, so a thread-local is sufficient. Server threads are pooled, so
 * the filter must {@link #clear()} in a finally block: influence left behind would be committed to another
 * request's calls, and a label to another request's response.
 */
public final class PaztportContext {

    private static final ThreadLocal<List<StampV3>> INBOUND = new ThreadLocal<>();
    private static final ThreadLocal<List<InfluenceEntry>> INFLUENCE = ThreadLocal.withInitial(ArrayList::new);
    private static final ThreadLocal<List<ContentLabel>> LABELS = ThreadLocal.withInitial(ArrayList::new);

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

    public static void clear() {
        INBOUND.remove();
        INFLUENCE.remove();
        LABELS.remove();
    }
}
