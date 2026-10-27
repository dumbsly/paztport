// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

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
}
