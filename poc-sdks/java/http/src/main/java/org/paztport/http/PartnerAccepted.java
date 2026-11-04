// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.VerifyResult;

/**
 * What {@link PartnerReceiver#accept} decided about another organisation's call: a refusal to send in place of the
 * handler's answer, or a call served in an unsafe session, where nothing from the request is believed, or in an
 * attested one, where the call verified in that session.
 *
 * <p>Only a receiver makes one: there is no other constructor, and the class cannot be extended. So a chain it says
 * verified passed the live order in its session at this hop, and the request context marks it verified only from here.
 */
public final class PartnerAccepted {

    private static final PartnerAccepted UNSAFE = new PartnerAccepted(null, null, List.of(), null);

    private final HttpAnswer refusal;
    private final List<Stamp> chain;
    private final List<InfluenceEntry> influence;
    private final VerifyResult result;

    private PartnerAccepted(HttpAnswer refusal, List<Stamp> chain, List<InfluenceEntry> influence,
            VerifyResult result) {
        this.refusal = refusal;
        this.chain = chain;
        this.influence = influence;
        this.result = result;
    }

    /** @param result the session verifier's result the call was refused for, or null when none ran */
    static PartnerAccepted refused(HttpAnswer refusal, VerifyResult result) {
        return new PartnerAccepted(refusal, null, List.of(), result);
    }

    static PartnerAccepted unsafe() {
        return UNSAFE;
    }

    static PartnerAccepted attested(List<Stamp> chain, List<InfluenceEntry> influence, VerifyResult result) {
        return new PartnerAccepted(null, List.copyOf(chain), List.copyOf(influence), result);
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
    public List<Stamp> verifiedChain() {
        return chain;
    }

    /** The verified influence, owners included, when {@link #attested}; otherwise none, whatever headers came. */
    public List<InfluenceEntry> influence() {
        return influence;
    }

    /**
     * The session verifier's result on the call, or null when no verification ran: in an unsafe session, or when the
     * session is unknown. The caller is never told it.
     */
    public VerifyResult result() {
        return result;
    }
}
