// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * A typed verification outcome. {@code suspectSvc}/{@code suspectInst} name the
 * last service and instance the verifier could attribute the request to (for
 * the responder's quarantine decision); they may be empty when the chain is
 * missing or unreadable.
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
