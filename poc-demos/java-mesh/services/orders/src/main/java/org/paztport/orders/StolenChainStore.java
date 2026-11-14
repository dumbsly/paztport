// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain orders served through {@code getOrder}, the last through {@code createOrder} and
 * the last through {@code holdItems}, each with the blocks it came with, so the attack endpoints can steer a call to
 * payment from any of them. It exists only when {@code attack.enabled=true}, and models code in orders reusing the
 * chains it was handed.
 *
 * <p>The blocks are kept because a stamp commits to its block: a chain sent on without them, where any stamp's block
 * was not the empty one, fails check 9a at payment before the check each attack is meant to meet.
 */
@Component
@ConditionalOnProperty(name = "attack.enabled", havingValue = "true")
public class StolenChainStore {

    /**
     * A chain orders was handed and the blocks that came with it, one per stamp.
     *
     * @param chain the stamps, origin first
     * @param blocks one block per stamp, in chain order
     */
    public record Stolen(List<Stamp> chain, List<Block> blocks) {
    }

    private final AtomicReference<Stolen> getOrder = new AtomicReference<>();
    private final AtomicReference<Stolen> createOrder = new AtomicReference<>();
    private final AtomicReference<Stolen> holdItems = new AtomicReference<>();

    /** Keeps a chain served through {@code getOrder} and its blocks; see {@link #record}. */
    public void recordGetOrder(List<Stamp> chain, List<Block> blocks) {
        record(getOrder, chain, blocks);
    }

    /** Keeps a chain served through {@code holdItems} and its blocks; see {@link #record}. */
    public void recordHoldItems(List<Stamp> chain, List<Block> blocks) {
        record(holdItems, chain, blocks);
    }

    /** Keeps a chain served through {@code createOrder} and its blocks; see {@link #record}. */
    public void recordCreateOrder(List<Stamp> chain, List<Block> blocks) {
        record(createOrder, chain, blocks);
    }

    /** The last chain served through {@code getOrder}, with its blocks, or null before any. */
    public Stolen getOrder() {
        return getOrder.get();
    }

    /** The last chain served through {@code createOrder}, with its blocks, or null before any. */
    public Stolen createOrder() {
        return createOrder.get();
    }

    /** The last chain served through {@code holdItems}, with its blocks, or null before any. */
    public Stolen holdItems() {
        return holdItems.get();
    }

    /**
     * Keeps {@code chain} with {@code blocks}, unless there is no chain. A served chain always has its blocks
     * ({@code RequestContext.inboundBlocks()}), so a chain without them is not kept either.
     */
    private static void record(AtomicReference<Stolen> last, List<Stamp> chain, List<Block> blocks) {
        if (chain != null && !chain.isEmpty() && blocks != null) {
            last.set(new Stolen(chain, blocks));
        }
    }
}
