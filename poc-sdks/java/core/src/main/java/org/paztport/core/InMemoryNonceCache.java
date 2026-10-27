// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory, process-local replay guard. The no-argument form never forgets,
 * which is unbounded and fine for the POC; the ttl form drops a key once it is
 * older than the ttl, so memory follows the freshness window.
 */
public final class InMemoryNonceCache implements NonceCache {

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final long ttlMs;

    public InMemoryNonceCache() {
        this(Long.MAX_VALUE);
    }

    public InMemoryNonceCache(long ttlMs) {
        this.ttlMs = ttlMs;
    }

    @Override
    public boolean seenBefore(String key, long now) {
        // One atomic step per key: keep a live record, replace an expired or absent one.
        boolean[] hit = {false};
        seen.compute(key, (k, recorded) -> {
            if (recorded != null && now - recorded <= ttlMs) {
                hit[0] = true;
                return recorded;
            }
            return now;
        });
        if (ttlMs != Long.MAX_VALUE) {
            seen.values().removeIf(recorded -> now - recorded > ttlMs);
        }
        return hit[0];
    }

    @Override
    public long ttlMs() {
        return ttlMs;
    }
}
