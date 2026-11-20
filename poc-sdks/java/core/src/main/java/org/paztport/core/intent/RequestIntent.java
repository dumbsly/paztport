// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import org.paztport.core.verify.ReasonCode;

/**
 * What the items handed on under intent hold for a request (spec intent.md, The receiver's part, P1), as
 * {@link Intent#readRequest} reads them: the origin's facts when the items read, otherwise the signer of the first
 * block holding items that do not, for the operator's log, since the code names no one.
 *
 * @param facts the origin's facts; {@link IntentFacts#NONE} when it stated none or the items do not read
 * @param unreadSigner the signer of the first block holding items that do not read; null when they read
 */
public record RequestIntent(IntentFacts facts, String unreadSigner) {

    /**
     * @throws IllegalArgumentException facts beside an unread signer, where nothing is believed
     */
    public RequestIntent {
        if (facts == null || (unreadSigner != null && !facts.isEmpty())) {
            throw new IllegalArgumentException("a request whose items do not read holds no facts");
        }
    }

    /** Whether the items handed on read. */
    public boolean reads() {
        return unreadSigner == null;
    }

    /**
     * The code a request whose items do not read is refused (spec intent.md, Reason codes): {@code INTENT_MISMATCH};
     * null when they read, and P2 decides.
     */
    public ReasonCode reason() {
        return reads() ? null : ReasonCode.INTENT_MISMATCH;
    }
}
