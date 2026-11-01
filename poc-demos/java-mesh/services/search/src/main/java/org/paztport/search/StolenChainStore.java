// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.stamp.Stamp;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain search legitimately received (from gateway), so an
 * attack endpoint can maliciously forward it onward. This models an attacker
 * reusing a chain it was handed.
 */
@Component
public class StolenChainStore {

    private final AtomicReference<List<Stamp>> last = new AtomicReference<>();

    public void record(List<Stamp> chain) {
        if (chain != null && !chain.isEmpty()) {
            last.set(chain);
        }
    }

    public List<Stamp> last() {
        return last.get();
    }
}
