// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.PathChain;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain search legitimately received (from gateway), so an
 * attack endpoint can maliciously forward it onward. This models an attacker
 * reusing a chain it was handed.
 */
@Component
public class StolenChainStore {

    private final AtomicReference<PathChain> last = new AtomicReference<>();

    public void record(PathChain chain) {
        if (chain != null && !chain.stamps().isEmpty()) {
            last.set(chain);
        }
    }

    public PathChain last() {
        return last.get();
    }
}
