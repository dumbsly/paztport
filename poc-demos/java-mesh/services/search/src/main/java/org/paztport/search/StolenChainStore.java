// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.paztport.core.StampV3;
import org.springframework.stereotype.Component;

/**
 * Holds the last inbound chain search legitimately received (from gateway), so an
 * attack endpoint can maliciously forward it onward. This models an attacker
 * reusing a chain it was handed.
 */
@Component
public class StolenChainStore {

    private final AtomicReference<List<StampV3>> last = new AtomicReference<>();

    public void record(List<StampV3> chain) {
        if (chain != null && !chain.isEmpty()) {
            last.set(chain);
        }
    }

    public List<StampV3> last() {
        return last.get();
    }
}
