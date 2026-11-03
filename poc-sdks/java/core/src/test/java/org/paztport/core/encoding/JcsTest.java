// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JcsTest {

    @Test
    void rfc8785KeyOrder() {
        String in = "{\"\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\","
                + "\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\","
                + "\"\ud83d\ude00\":\"Emoji: Grinning Face\",\"\u0080\":\"Control\","
                + "\"\u00f6\":\"Latin Small Letter O With Diaeresis\"}";
        assertEquals(
                "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\","
                        + "\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\","
                        + "\"\ud83d\ude00\":\"Emoji: Grinning Face\","
                        + "\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
                Jcs.canonicalize(in));
    }

    @Test
    void escapes() {
        assertEquals(
                "\"q\\\"b\\\\s/\\b\\f\\n\\r\\t\\u001f\"",
                Jcs.canonicalize("\"q\\\"b\\\\s/\\b\\f\\n\\r\\t\\u001f\""));
    }

    @Test
    void rejects() {
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("\"\\ud800\""));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("{\"\\ud800\":1}"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("1.5"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("9007199254740992"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("-9007199254740992"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("-1"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("{\"a\":1,\"a\":2}"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("123456789012345678901234567890"));
    }

    /** Text that is not exactly one JSON value has no canonical form: malformed, empty, or followed by more. */
    @Test
    void rejectsWhatIsNotOneValue() {
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("{\"a\":"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("[1] [2]"));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("  "));
        assertThrows(MalformedJsonException.class, () -> Jcs.bytes("nul"));
    }

    @Test
    void integersAndOrder() {
        assertEquals("[3,1,0,true,null,{\"a\":2,\"b\":1},9007199254740991]",
                Jcs.canonicalize(" [3, 1, 0, true, null, {\"b\": 1, \"a\": 2}, 9007199254740991] "));
    }

    @Test
    void bytesAreUtf8() {
        assertArrayEquals("\"\u20ac\"".getBytes(StandardCharsets.UTF_8), Jcs.bytes("\"\u20ac\""));
    }

    @Test
    void onlyJsonNullPrintsNull() {
        assertEquals("null", Jcs.canonicalize("null"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(null));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize(""));
        assertThrows(MalformedJsonException.class, () -> Jcs.canonicalize("{\"a\":1.0}"));
    }
}
