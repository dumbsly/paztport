// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NonceCacheTest {

    @Test
    void firstSightingIsNotAReplayButRecordsIt() {
        NonceCache cache = new InMemoryNonceCache();
        assertFalse(cache.seenBefore("rid-1", "orders"));
        assertTrue(cache.seenBefore("rid-1", "orders"));
    }

    @Test
    void differentRidOrSvcAreTrackedSeparately() {
        NonceCache cache = new InMemoryNonceCache();
        cache.seenBefore("rid-1", "orders");
        assertFalse(cache.seenBefore("rid-2", "orders"));
        assertFalse(cache.seenBefore("rid-1", "search"));
    }
}
