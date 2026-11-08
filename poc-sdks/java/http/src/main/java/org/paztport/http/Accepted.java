// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.NonceCacheUnavailableException;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.wire.HttpWire;

/**
 * What {@link HttpReceiver#accept} decided about one request: a refusal to send in place of the handler's answer,
 * or what the handler starts from, whether its answer may be attested, and the verification result that decided it.
 *
 * <p>Only a receiver makes one: there is no other constructor, and the class cannot be extended. So a chain it says
 * verified passed the full live order at this hop, and the request context marks that chain verified only from here.
 */
public final class Accepted {

    private final HttpAnswer refusal;
    private final List<Stamp> inbound;
    private final boolean verified;
    private final List<InfluenceEntry> influence;
    private final Stamper attester;
    private final VerifyResult result;
    private final NonceCacheUnavailableException cacheFailure;
    private final String operation;

    private Accepted(HttpAnswer refusal, List<Stamp> inbound, boolean verified, List<InfluenceEntry> influence,
            Stamper attester, VerifyResult result, NonceCacheUnavailableException cacheFailure, String operation) {
        this.refusal = refusal;
        this.inbound = inbound;
        this.verified = verified;
        this.influence = influence;
        this.attester = attester;
        this.result = result;
        this.cacheFailure = cacheFailure;
        this.operation = operation;
    }

    /** @param result the result the request was refused for, or null when no verification ran */
    static Accepted refused(HttpAnswer refusal, VerifyResult result) {
        return new Accepted(refusal, null, false, List.of(), null, result, null, null);
    }

    /** The request refused as unavailable because the nonce cache could not answer: no result, and the failure. */
    static Accepted unavailable(NonceCacheUnavailableException cacheFailure) {
        return new Accepted(HttpAnswer.unavailable(), null, false, List.of(), null, null, cacheFailure, null);
    }

    /**
     * @param attester the stamper to attest with, only where the chain verified here and this service attests;
     *     otherwise null
     * @param result the live order's result on the request, or null when it did not run or the nonce cache could not
     *     answer
     * @param cacheFailure why the nonce cache could not answer, or null
     * @param operation the operation the request was verified as received by, or null ({@link #operation})
     */
    static Accepted served(List<Stamp> inbound, boolean verified, List<InfluenceEntry> influence,
            Stamper attester, VerifyResult result, NonceCacheUnavailableException cacheFailure, String operation) {
        return new Accepted(null, inbound, verified, List.copyOf(influence), attester, result, cacheFailure,
                operation);
    }

    /**
     * The operation a served request was verified as received by, the operation part of {@code <service>#<operation>}:
     * the one the adapter said the request will be dispatched to, where the chain named an operation and the live
     * order ran on the request, under a mode or for attestation alone, whether or not it passed. Null where the chain
     * named none, so the request was verified under the service alone, where nothing was verified, and for a refusal.
     * An adapter whose framework can change the handler after this was decided checks, as the handler runs, that it
     * is still this operation's.
     */
    public String operation() {
        return operation;
    }

    /** The answer to send in place of the handler's, or null when the request is served. */
    public HttpAnswer refusal() {
        return refusal;
    }

    /**
     * The chain the request carried, for the handler's own calls to stamp onto; null when none came, it did not
     * parse, or this service is an origin, which starts a new request tree.
     */
    public List<Stamp> inbound() {
        return inbound;
    }

    /**
     * {@link #inbound} when it passed the live order at this hop, otherwise null: a chain that failed in audit, was
     * not checked (the hop is off, or verifies nothing), or came to an origin gives null.
     */
    public List<Stamp> verifiedChain() {
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
     * The live order's result on the request, or null when it did not run. Under a mode it is the result to report,
     * a refusal's included; for a service with no mode it decided only whether to attest. The caller is never told it.
     */
    public VerifyResult result() {
        return result;
    }

    /**
     * Why the nonce cache could not answer, or null when it did or was not asked. The request then has no verdict:
     * under {@code ENFORCE} it is refused ({@link #refusal} is 503, empty), and otherwise it is served with its chain
     * unverified and its answer unattested.
     */
    public NonceCacheUnavailableException cacheFailure() {
        return cacheFailure;
    }

    /**
     * The delivery this request names, when {@link #verifiedChain} is not null: the first stamp's {@code rid} and the
     * last stamp's {@code svc} and {@code bind}. Otherwise null.
     */
    public Delivery delivery() {
        if (!verified) {
            return null;
        }
        Stamp last = inbound.get(inbound.size() - 1);
        return new Delivery(inbound.get(0).rid(), last.svc(), last.bind());
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
            String hash = HttpWire.resultHash(status, body);
            Stamp stamp = attester.respond(inbound, hash, rid, labels);
            return HttpWire.encodeResponse(stamp, labels);
        } catch (IllegalArgumentException e) {
            // Served unattested, so the caller records it as local-untrusted; the operator learns why here.
            HttpReceiver.LOG.warn("response left unattested: rid={} {}", LogSafe.of(rid), LogSafe.of(e.getMessage()));
            return null;
        }
    }
}
