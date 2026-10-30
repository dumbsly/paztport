// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;

/**
 * What {@link PartnerReceiver#accept} decided about another organisation's call: a refusal to send in place of the
 * handler's answer, or a call served in an unsafe session, where nothing from the request is believed, or in an
 * attested one, where the call verified in that session.
 *
 * <p>Only a receiver makes one, so a chain it says verified passed the live order in its session at this hop: there
 * is no other constructor, and the class cannot be extended.
 */
public final class PartnerAccepted {

    private static final PartnerAccepted UNSAFE = new PartnerAccepted(null, null, List.of());

    private final HttpAnswer refusal;
    private final List<StampV3> chain;
    private final List<InfluenceEntry> influence;

    private PartnerAccepted(HttpAnswer refusal, List<StampV3> chain, List<InfluenceEntry> influence) {
        this.refusal = refusal;
        this.chain = chain;
        this.influence = influence;
    }

    static PartnerAccepted refused(HttpAnswer refusal) {
        return new PartnerAccepted(refusal, null, List.of());
    }

    static PartnerAccepted unsafe() {
        return UNSAFE;
    }

    static PartnerAccepted attested(List<StampV3> chain, List<InfluenceEntry> influence) {
        return new PartnerAccepted(null, List.copyOf(chain), List.copyOf(influence));
    }

    /** The answer to send in place of the handler's, or null when the call is served. */
    public HttpAnswer refusal() {
        return refusal;
    }

    /**
     * Whether the call is served in an attested session, having verified there; false in an unsafe session and for
     * a refusal, so nothing downstream could take a refused call for attested.
     */
    public boolean attested() {
        return chain != null;
    }

    /** The chain that verified in the session, or null unless {@link #attested}. */
    public List<StampV3> verifiedChain() {
        return chain;
    }

    /** The verified influence, owners included, when {@link #attested}; otherwise none, whatever headers came. */
    public List<InfluenceEntry> influence() {
        return influence;
    }
}
