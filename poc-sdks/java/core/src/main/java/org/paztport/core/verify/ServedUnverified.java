// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.List;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;

/**
 * What a service does with the blocks of a request it is about to serve without having verified it: in audit mode
 * after a failure, with no verifier, where it runs the live order only to attest, or with Paztport off (spec
 * verification.md, "A service never serves a request whose blocks fail check 9a" and "What a request served without
 * verifying is handed"). It needs no key.
 *
 * <p>Only check 9a applies. Checks 9b and 9c follow the mode, and the caller already has the verifier's result for
 * them where it ran one. The hand-over is never verified, so {@link HandOver#requireFor} does not apply to it.
 */
public final class ServedUnverified {

    private final boolean match;
    private final HandOver handOver;

    private ServedUnverified(boolean match, HandOver handOver) {
        this.match = match;
        this.handOver = handOver;
    }

    /**
     * Applies check 9a where the chain reads, and otherwise only requires the blocks to read as an array of blocks
     * (none received reads), since a chain that did not read has no stamps to match them to.
     *
     * @param stamps the chain's JSON text as received, null for none
     * @param blocks the blocks' JSON text as received, null for none
     * @param settings the extensions the service acts on
     */
    public static ServedUnverified of(String stamps, String blocks, ExtensionSettings settings) {
        ParsedChain parsed = Chains.parse(stamps);
        if (!parsed.ok()) {
            try {
                ChainChecks.readBlocks(blocks);
            } catch (IllegalArgumentException e) {
                return new ServedUnverified(false, null);
            }
            return new ServedUnverified(true, null);
        }
        ChainChecks.BlocksCheck checked = ChainChecks.checkMatch(parsed.stamps(), blocks);
        if (checked.failure() != null) {
            return new ServedUnverified(false, null);
        }
        List<Block> read = checked.blocks();
        return new ServedUnverified(true, new HandOver(false, parsed.stamps(), read, settings));
    }

    /** False: the request is not served; over HTTP it is answered 400 EXTENSION_MISMATCH. */
    public boolean blocksMatch() {
        return match;
    }

    /** The items handed on, not verified; null when {@link #blocksMatch} is false and when the chain did not read. */
    public HandOver handOver() {
        return handOver;
    }
}
