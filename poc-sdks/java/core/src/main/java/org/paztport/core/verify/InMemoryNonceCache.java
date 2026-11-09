// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory, process-local replay guard. The no-argument form never forgets,
 * which is unbounded and fine for the POC; the ttl form drops a key once it is
 * older than the ttl, so memory follows the freshness window. Expired keys are swept at most once per half ttl;
 * between sweeps an expired key may still be stored, but it is never reported seen, since the check compares the
 * stored time.
 */
public final class InMemoryNonceCache implements NonceCache {

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final long ttlMs;
    private final long sweepIntervalMs;
    private final AtomicLong sweptAt = new AtomicLong(UNSWEPT);

    private static final long UNSWEPT = Long.MIN_VALUE;

    public InMemoryNonceCache() {
        this(Long.MAX_VALUE);
    }

    public InMemoryNonceCache(long ttlMs) {
        this.ttlMs = ttlMs;
        this.sweepIntervalMs = ttlMs / 2;
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
            sweepIfDue(now);
        }
        return hit[0];
    }

    /** Removes expired keys when a sweep interval has passed; one caller wins each interval. */
    private void sweepIfDue(long now) {
        long last = sweptAt.get();
        if (last == UNSWEPT) {
            // The first call has nothing to sweep: start the interval.
            sweptAt.compareAndSet(UNSWEPT, now);
        } else if ((now - last >= sweepIntervalMs || last - now >= sweepIntervalMs)
                && sweptAt.compareAndSet(last, now)) {
            // Also sweep when the clock reads an interval behind the last sweep, so a step back cannot stall sweeping.
            seen.values().removeIf(recorded -> now - recorded > ttlMs);
        }
    }

    @Override
    public long ttlMs() {
        return ttlMs;
    }
}
