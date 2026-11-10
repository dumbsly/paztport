// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.stamp.Stamp;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain orders served through {@code getOrder}, the last through {@code createOrder} and
 * the last through {@code holdItems}, so the attack endpoints can steer a call to payment from any of them. It exists
 * only when {@code attack.enabled=true}, and models code in orders reusing the chains it was handed.
 */
@Component
@ConditionalOnProperty(name = "attack.enabled", havingValue = "true")
public class StolenChainStore {

    private final AtomicReference<List<Stamp>> getOrder = new AtomicReference<>();
    private final AtomicReference<List<Stamp>> createOrder = new AtomicReference<>();
    private final AtomicReference<List<Stamp>> holdItems = new AtomicReference<>();

    public void recordGetOrder(List<Stamp> chain) {
        record(getOrder, chain);
    }

    public void recordHoldItems(List<Stamp> chain) {
        record(holdItems, chain);
    }

    public void recordCreateOrder(List<Stamp> chain) {
        record(createOrder, chain);
    }

    /** The last chain served through {@code getOrder}, or null before any. */
    public List<Stamp> getOrder() {
        return getOrder.get();
    }

    /** The last chain served through {@code createOrder}, or null before any. */
    public List<Stamp> createOrder() {
        return createOrder.get();
    }

    /** The last chain served through {@code holdItems}, or null before any. */
    public List<Stamp> holdItems() {
        return holdItems.get();
    }

    private static void record(AtomicReference<List<Stamp>> last, List<Stamp> chain) {
        if (chain != null && !chain.isEmpty()) {
            last.set(chain);
        }
    }
}
