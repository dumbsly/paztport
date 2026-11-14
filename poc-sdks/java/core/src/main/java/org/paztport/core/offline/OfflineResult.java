// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * An offline verdict, with the suspect as in {@link VerifyResult}, and as there the hand-over: non-null exactly when
 * the reason is {@code OK}, and then verified.
 */
public record OfflineResult(ReasonCode reason, String suspectSvc, String suspectInst, HandOver handOver) {

    /**
     * @throws IllegalArgumentException a hand-over on a result other than OK, none on OK, or one not verified
     */
    public OfflineResult {
        if ((reason == ReasonCode.OK) != (handOver != null) || (handOver != null && !handOver.verified())) {
            throw new IllegalArgumentException("a verifier hands over a verified hand-over exactly on OK");
        }
    }

    /** Whether every check held. */
    public boolean ok() {
        return reason == ReasonCode.OK;
    }
}
