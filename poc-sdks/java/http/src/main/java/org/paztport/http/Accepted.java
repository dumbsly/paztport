// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.wire.HttpV3;

/**
 * What {@link HttpReceiver#accept} decided about one request: a refusal to send in place of the handler's answer,
 * or what the handler starts from, and whether its answer may be attested.
 *
 * <p>Only a receiver makes one: there is no other constructor, and the class cannot be extended. So a chain it says
 * verified passed the full live order at this hop, and the request context marks that chain verified only from here.
 */
public final class Accepted {

    private final HttpAnswer refusal;
    private final List<StampV3> inbound;
    private final boolean verified;
    private final List<InfluenceEntry> influence;
    private final StamperV3 attester;

    private Accepted(HttpAnswer refusal, List<StampV3> inbound, boolean verified, List<InfluenceEntry> influence,
            StamperV3 attester) {
        this.refusal = refusal;
        this.inbound = inbound;
        this.verified = verified;
        this.influence = influence;
        this.attester = attester;
    }

    static Accepted refused(HttpAnswer refusal) {
        return new Accepted(refusal, null, false, List.of(), null);
    }

    /**
     * @param attester the stamper to attest with, only where the chain verified here and this service attests;
     *     otherwise null
     */
    static Accepted served(List<StampV3> inbound, boolean verified, List<InfluenceEntry> influence,
            StamperV3 attester) {
        return new Accepted(null, inbound, verified, List.copyOf(influence), attester);
    }

    /** The answer to send in place of the handler's, or null when the request is served. */
    public HttpAnswer refusal() {
        return refusal;
    }

    /**
     * The chain the request carried, for the handler's own calls to stamp onto; null when none came, it did not
     * parse, or this service is an origin, which starts a new request tree.
     */
    public List<StampV3> inbound() {
        return inbound;
    }

    /**
     * {@link #inbound} when it passed the live order at this hop, otherwise null: a chain that failed in audit, was
     * not checked (the hop is off, or verifies nothing), or came to an origin gives null.
     */
    public List<StampV3> verifiedChain() {
        return verified ? inbound : null;
    }

    /**
     * The influence the handler starts from: the verified entries when the request verified, otherwise the entries
     * as received; none at an origin, and none for a refusal.
     */
    public List<InfluenceEntry> influence() {
        return influence;
    }

    /**
     * Whether the answer to this request is attested: only for a chain that verified here, on a non-origin service
     * with a stamp key whose verification is not switched off. A framework holds the handler's body until it is
     * complete only when this is true.
     */
    public boolean attests() {
        return attester != null;
    }

    /**
     * The {@code X-Path-Response} header for the handler's complete answer, or null when it is not attested: one
     * stamp on {@link #inbound} back to the caller, binding {@code status}, {@code body} and {@code labels}. The chain
     * is the one the request carried, not anything the handler holds, so a handler cannot steer what is vouched for.
     * A rid or label the binding cannot carry leaves the answer unattested, with a warning, rather than failing it.
     *
     * <p>It takes the answer whole, and knows nothing of when that is: the framework calls it only once the handler
     * has finished with a body nothing else will change. An answer the framework cannot hold whole (one written after
     * the handler returned, or an error page the container writes after it) is not one to attest; the caller records
     * an unattested answer as untrusted.
     *
     * @param labels what the handler labelled its answer with, in order
     */
    public String attest(int status, byte[] body, List<ContentLabel> labels) {
        if (attester == null) {
            return null;
        }
        String rid = inbound.get(0).rid();
        try {
            String hash = HttpV3.resultHash(status, body);
            StampV3 stamp = attester.respond(inbound, hash, rid, labels);
            return HttpV3.encodeResponse(stamp, labels);
        } catch (IllegalArgumentException e) {
            // Served unattested, so the caller records it as local-untrusted; the operator learns why here.
            HttpReceiver.LOG.warn("response left unattested: rid={} {}", LogSafe.of(rid), LogSafe.of(e.getMessage()));
            return null;
        }
    }
}
