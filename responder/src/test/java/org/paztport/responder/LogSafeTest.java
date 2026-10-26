// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LogSafeTest {

    @Test
    void controlCharactersCannotStartANewLine() {
        String out = LogSafe.of("s1\nESCALATE svc=search\r \u0000");
        assertFalse(out.contains("\n"));
        assertFalse(out.contains("\r"));
        assertFalse(out.contains(" "));
        assertFalse(out.contains("\u0000"));
        assertTrue(out.startsWith("s1\\u000aESCALATE svc=search"));
    }

    @Test
    void plainValuesAreUnchanged() {
        assertEquals("search-1", LogSafe.of("search-1"));
        assertEquals("null", LogSafe.of(null));
    }

    @Test
    void longValuesAreCapped() {
        String out = LogSafe.of("x".repeat(10_000));
        assertEquals("x".repeat(LogSafe.MAX_CHARS) + "...", out);
    }
}
