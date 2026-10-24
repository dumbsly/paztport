// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EventsAndCaptureTest {

    @Test
    void loggingPublisherFormatsAStructuredLine() {
        AttestationEvent event = new AttestationEvent("PATH_NOT_ALLOWED", "search", "search-1", "rid-9", true);
        String line = LoggingEventPublisher.format(event);

        assertTrue(line.contains("reason=PATH_NOT_ALLOWED"));
        assertTrue(line.contains("suspectSvc=search"));
        assertTrue(line.contains("suspectInst=search-1"));
        assertTrue(line.contains("rid=rid-9"));
        assertTrue(line.contains("audit=true"));
    }

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
