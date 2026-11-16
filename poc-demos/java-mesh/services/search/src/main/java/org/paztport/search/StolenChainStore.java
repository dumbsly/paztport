// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain search legitimately received (from gateway), with the blocks that came with it, so an
 * attack endpoint can maliciously forward it onward. This models an attacker reusing a chain it was handed.
 *
 * <p>The blocks are kept because a stamp commits to its block: a chain forwarded without them, where any stamp's
 * block was not the empty one, fails check 9a at payment before the check each attack is meant to meet.
 */
@Component
public class StolenChainStore {

    /**
     * A chain search was handed and the blocks that came with it, one per stamp.
     *
     * @param chain the stamps, origin first
     * @param blocks one block per stamp, in chain order
     */
    public record Stolen(List<Stamp> chain, List<Block> blocks) {
    }

    private final AtomicReference<Stolen> last = new AtomicReference<>();

    /**
     * Keeps {@code chain} with {@code blocks}, unless there is no chain. A served chain always has its blocks
     * ({@code RequestContext.inboundBlocks()}), so a chain without them is not kept either.
     */
    public void record(List<Stamp> chain, List<Block> blocks) {
        if (chain != null && !chain.isEmpty() && blocks != null) {
            last.set(new Stolen(chain, blocks));
        }
    }

    /** The last chain kept, with its blocks, or null before any. */
    public Stolen last() {
        return last.get();
    }
}
