// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

/**
 * A typed verification outcome. {@code suspectSvc}/{@code suspectInst} name who
 * sent this request, for the responder's quarantine decision.
 *
 * <p>When the input names a peer (the sender a transport authenticated, as
 * under mutual TLS), every result, {@code OK} and every rejection alike, names
 * that peer: its service and the address it connected from. The peer's identity
 * does not depend on the chain, so it can be blamed whatever the chain says.
 * The one exception is {@code POLICY_EXPIRED}, which names no one: it is about
 * the verifier's own pinned policy, and expiry is not the sender's fault.
 *
 * <p>Without a peer, they name the last service that provably sent this
 * request, proven by its key, and the instance that service reported in its
 * stamp; the instance is the key holder's own claim, not something the verifier
 * can check. Then they are set only for {@code OK} and
 * {@code PATH_NOT_ALLOWED}; every other rejection leaves them empty, because
 * the name would be unsigned or the genuine stamp would belong to another
 * request. See {@link VerifierV1} for the forwarding case that is still blamed.
 */
public record VerifyResult(ReasonCode reason, String suspectSvc, String suspectInst) {

    public boolean ok() {
        return reason == ReasonCode.OK;
    }

    static VerifyResult ok(String svc, String inst) {
        return new VerifyResult(ReasonCode.OK, svc, inst);
    }

    static VerifyResult reject(ReasonCode reason) {
        return new VerifyResult(reason, "", "");
    }

    static VerifyResult reject(ReasonCode reason, String svc, String inst) {
        return new VerifyResult(reason, svc, inst);
    }
}
