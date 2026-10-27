// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JcsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
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
                Jcs.canonicalize(o));
    }

    @Test
    void escapes() {
        assertEquals(
                "\"q\\\"b\\\\s/\\b\\f\\n\\r\\t\\u001f\"",
                Jcs.canonicalize(F.textNode("q\"b\\s/\b\f\n\r\t\u001f")));
    }

    @Test
    void rejects() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(F.textNode("\ud800")));
        ObjectNode key = F.objectNode();
        key.put("\ud800", 1);
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(key));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(MAPPER.readTree("1.5")));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(MAPPER.readTree("9007199254740992")));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(MAPPER.readTree("-9007199254740992")));
        assertThrows(IllegalArgumentException.class,
                () -> Jcs.canonicalize(MAPPER.readTree("123456789012345678901234567890")));
    }

    @Test
    void integersAndOrder() throws Exception {
        JsonNode n = MAPPER.readTree("[3,-1,0,true,null,{\"b\":1,\"a\":2},9007199254740991]");
        assertEquals("[3,-1,0,true,null,{\"a\":2,\"b\":1},9007199254740991]", Jcs.canonicalize(n));
    }

    @Test
    void bytesAreUtf8() {
        assertArrayEquals("\"\u20ac\"".getBytes(StandardCharsets.UTF_8), Jcs.bytes(F.textNode("\u20ac")));
    }
}
