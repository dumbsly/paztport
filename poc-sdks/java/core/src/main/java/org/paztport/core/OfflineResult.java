// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * An offline verdict, with the suspect as in {@link VerifyResult}, and whether the chain was legacy: true once an
 * all-v2 chain passes checks 1 to 6, whatever a later check gives; false for a v3 chain and for any chain
 * rejected at checks 1 to 6.
 */
public record OfflineResult(ReasonCode reason, String suspectSvc, String suspectInst, boolean legacy) {

    public boolean ok() {
        return reason == ReasonCode.OK;
    }
}
