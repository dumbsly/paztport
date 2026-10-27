// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * A typed verification outcome. {@code suspectSvc}/{@code suspectInst} name the
 * last service that provably sent this request, proven by its key, and the
 * instance that service reported in its stamp (for the responder's quarantine
 * decision). The instance is the key holder's own claim, not something the
 * verifier can check. They are set only for {@code OK} and
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
