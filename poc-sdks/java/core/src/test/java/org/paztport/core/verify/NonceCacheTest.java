// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NonceCacheTest {

    @Test
    void neverForgetsByDefault() {
        NonceCache cache = new InMemoryNonceCache();
        assertFalse(cache.seenBefore("k", 0));
        assertTrue(cache.seenBefore("k", Long.MAX_VALUE / 2));
        assertEquals(Long.MAX_VALUE, cache.ttlMs());
    }

    @Test
    void forgetsAfterTtl() {
        NonceCache cache = new InMemoryNonceCache(15_000);
        assertFalse(cache.seenBefore("k", 1000));
        assertTrue(cache.seenBefore("k", 15_999));
        // The hit above did not refresh the record, so 16_001 is past 1000 + 15_000.
        assertFalse(cache.seenBefore("k", 16_001));
    }

    @Test
    void keysAreExact() {
        NonceCache cache = new InMemoryNonceCache();
        assertFalse(cache.seenBefore("a|b", 0));
        assertFalse(cache.seenBefore("a|c", 0));
        assertTrue(cache.seenBefore("a|b", 0));
    }

    @Test
    void expiredKeyIsNotSeenBetweenSweeps() {
        NonceCache cache = new InMemoryNonceCache(1000);
        assertFalse(cache.seenBefore("a", 0));
        // The sweep at 600 keeps "a"; the next is not due until 1100, so "a" is still stored at 1001, past its ttl.
        assertFalse(cache.seenBefore("x", 600));
        assertFalse(cache.seenBefore("a", 1001));
    }

    @Test
    void liveKeyIsSeenBetweenSweeps() {
        NonceCache cache = new InMemoryNonceCache(1000);
        assertFalse(cache.seenBefore("a", 0));
        assertFalse(cache.seenBefore("b", 400));
        assertTrue(cache.seenBefore("a", 900));
        assertTrue(cache.seenBefore("a", 1000));
        // A sweep at 1400 drops "a" and keeps "b".
        assertFalse(cache.seenBefore("c", 1400));
        assertTrue(cache.seenBefore("b", 1400));
        assertFalse(cache.seenBefore("a", 1400));
    }

    @Test
    void sweepsAgainAfterTheClockStepsBack() throws Exception {
        InMemoryNonceCache cache = new InMemoryNonceCache(1000);
        assertFalse(cache.seenBefore("far", 1_000_000));
        for (long t = 0; t <= 20_000; t += 10) {
            assertFalse(cache.seenBefore("k" + t, t));
        }
        java.lang.reflect.Field field = InMemoryNonceCache.class.getDeclaredField("seen");
        field.setAccessible(true);
        // Steady-clock bound is about ttl / step = 100 live keys, plus "far".
        assertTrue(((java.util.Map<?, ?>) field.get(cache)).size() < 200);
    }
}
