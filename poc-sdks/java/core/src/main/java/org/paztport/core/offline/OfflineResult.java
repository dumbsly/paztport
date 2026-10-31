// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * An offline verdict, with the suspect as in {@link VerifyResult}.
 */
public record OfflineResult(ReasonCode reason, String suspectSvc, String suspectInst) {

    public boolean ok() {
        return reason == ReasonCode.OK;
    }
}
