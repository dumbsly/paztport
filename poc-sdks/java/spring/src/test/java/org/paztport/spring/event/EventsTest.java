// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.paztport.spring.internal.LogSafe;

class EventsTest {

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
    void loggingPublisherKeepsAForgedNewlineOnOneLine() {
        AttestationEvent event = new AttestationEvent(
                "PATH_NOT_ALLOWED", "search", "s1\nPAZTPORT_EVENT reason=OK", "rid\r9", false);
        String line = LoggingEventPublisher.format(event);

        assertFalse(line.contains("\n"), line);
        assertFalse(line.contains("\r"), line);
        assertTrue(line.contains("suspectInst=s1\\u000aPAZTPORT_EVENT"), line);
    }

    @Test
    void logSafeCapsLongValues() {
        assertEquals("x".repeat(LogSafe.MAX_CHARS) + "...", LogSafe.of("x".repeat(10_000)));
        assertEquals("null", LogSafe.of(null));
    }
}
