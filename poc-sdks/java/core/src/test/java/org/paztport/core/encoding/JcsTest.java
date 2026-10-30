// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JcsTest {

    private static final JsonNodeFactory F = JsonNodeFactory.instance;

    @Test
    void rfc8785KeyOrder() {
        ObjectNode o = F.objectNode();
        o.put("\u20ac", "Euro Sign");
        o.put("\r", "Carriage Return");
        o.put("\ufb33", "Hebrew Letter Dalet With Dagesh");
        o.put("1", "One");
        o.put("\ud83d\ude00", "Emoji: Grinning Face");
        o.put("\u0080", "Control");
        o.put("\u00f6", "Latin Small Letter O With Diaeresis");
        assertEquals(
                "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\ud83d\ude00\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
                Jcs.canonicalize(o.toString()));
    }

    @Test
    void escapes() {
        assertEquals(
                "\"q\\\"b\\\\s/\\b\\f\\n\\r\\t\\u001f\"",
                Jcs.canonicalize(F.textNode("q\"b\\s/\b\f\n\r\t\u001f").toString()));
    }

    @Test
    void rejects() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("\"\\ud800\""));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("{\"\\ud800\":1}"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("1.5"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("9007199254740992"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("-9007199254740992"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("123456789012345678901234567890"));
    }

    /** Text that is not exactly one JSON value has no canonical form: malformed, empty, or followed by more. */
    @Test
    void rejectsWhatIsNotOneValue() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("{\"a\":"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("[1] [2]"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("  "));
        assertThrows(IllegalArgumentException.class, () -> Jcs.bytes("nul"));
    }

    @Test
    void integersAndOrder() {
        assertEquals("[3,-1,0,true,null,{\"a\":2,\"b\":1},9007199254740991]",
                Jcs.canonicalize(" [3, -1, 0, true, null, {\"b\": 1, \"a\": 2}, 9007199254740991] "));
    }

    @Test
    void bytesAreUtf8() {
        assertArrayEquals("\"\u20ac\"".getBytes(StandardCharsets.UTF_8), Jcs.bytes("\"\u20ac\""));
    }

    @Test
    void onlyJsonNullPrintsNull() {
        assertEquals("null", Jcs.canonicalize("null"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(null));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(""));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("{\"a\":1.0}"));
    }
}
