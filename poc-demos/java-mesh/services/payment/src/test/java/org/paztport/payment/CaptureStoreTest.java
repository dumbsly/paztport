// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CaptureStoreTest {

    @Test
    void captureStoreKeepsTheLastRequest() {
        CaptureStore store = new CaptureStore();
        assertTrue(store.last().isEmpty());

        store.record(new CapturedRequest("chainA", "proofA", "POST", "/pay", "bodyA".getBytes()));
        store.record(new CapturedRequest("chainB", "proofB", "POST", "/pay", "bodyB".getBytes()));

        assertTrue(store.last().isPresent());
        assertEquals("chainB", store.last().get().chainHeader());
        assertFalse(store.last().get().chainHeader().equals("chainA"));
    }
}
