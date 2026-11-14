// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.util.List;
import org.paztport.core.verify.ReasonCode;

/**
 * What the items handed on under influence hold for a request (spec influence.md, The every-stamp rule and Entries),
 * as {@link Influence#readRequest} reads them: when every item reads as an entry, the entries and whether every stamp
 * names influence; otherwise the signer of the first block holding an item that does not, for the operator's log,
 * since the code names no one. What the service adds itself is the caller's to add.
 *
 * @param entries every item of every block, read as an entry, in chain order; empty when an item does not read
 * @param everyStampNames whether every stamp's block names influence: true where there is no stamp to read, since
 *        the rule cannot refuse for what it is not shown (What the rules read); false when an item does not read,
 *        since no rule is reached then
 * @param unreadSigner the signer of the first block holding an item that does not read; null when every item reads
 */
public record RequestInfluence(List<InfluenceEntry> entries, boolean everyStampNames, String unreadSigner) {

    /**
     * Copies the entries.
     *
     * @throws IllegalArgumentException entries or everyStampNames beside an unread signer, where no rule reads them
     */
    public RequestInfluence {
        entries = List.copyOf(entries);
        if (unreadSigner != null && (everyStampNames || !entries.isEmpty())) {
            throw new IllegalArgumentException("a request whose items do not read holds no entries");
        }
    }

    /** Whether every item handed on reads as an entry. */
    public boolean reads() {
        return unreadSigner == null;
    }

    /**
     * The code a request holding an item that does not read is refused (spec influence.md, Entries):
     * {@code INFLUENCE_MISMATCH}, the one place the code is given for it; null when every item reads, and the rules
     * decide.
     */
    public ReasonCode reason() {
        return reads() ? null : ReasonCode.INFLUENCE_MISMATCH;
    }
}
