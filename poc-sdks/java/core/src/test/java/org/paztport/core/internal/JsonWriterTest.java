// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.MalformedJsonException.Step;

class JsonWriterTest {

    private static JsonValue.Obj obj(Object... nameThenValue) {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        for (int i = 0; i < nameThenValue.length; i += 2) {
            members.put((String) nameThenValue[i], (JsonValue) nameThenValue[i + 1]);
        }
        return new JsonValue.Obj(members);
    }

    private static JsonValue nested(int depth) {
        JsonValue v = new JsonValue.Arr(List.of());
        for (int i = 1; i < depth; i++) {
            v = new JsonValue.Arr(List.of(v));
        }
        return v;
    }

    /** Every form refuses the value at the WRITE step. */
    private static void refusedEverywhere(JsonValue v) {
        refusedOnTheWire(v);
        MalformedJsonException e = assertThrows(MalformedJsonException.class, () -> JsonWriter.file(v));
        assertEquals(Step.WRITE, e.step(), e.getMessage());
    }

    private static void refusedOnTheWire(JsonValue v) {
        for (MalformedJsonException e : List.of(
                assertThrows(MalformedJsonException.class, () -> JsonWriter.wire(v)),
                assertThrows(MalformedJsonException.class, () -> JsonWriter.text(v)),
                assertThrows(MalformedJsonException.class, () -> JsonWriter.token(v)))) {
            assertEquals(Step.WRITE, e.step(), e.getMessage());
        }
    }

    @Test
    void writesCanonicalBytes() {
        JsonValue v = obj(
                "\uFB33", new JsonValue.Int(1),
                "\uD83D\uDE00", new JsonValue.Int(0),
                "b", new JsonValue.Arr(List.of(new JsonValue.Bool(true), new JsonValue.Null())),
                "a", new JsonValue.Str("\"\\\b\f\n\r\t\u0000\u001f/\u007f\u00e9"));
        String jcs = "{\"a\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/\u007f\u00e9\",\"b\":[true,null],"
                + "\"\uD83D\uDE00\":0,\"\uFB33\":1}";
        assertEquals(jcs, JsonWriter.text(v));
        assertArrayEquals(jcs.getBytes(StandardCharsets.UTF_8), JsonWriter.wire(v));
    }

    @Test
    void refusesWhatTheReaderRefuses() {
        refusedEverywhere(new JsonValue.Str("\uD800"));
        refusedEverywhere(new JsonValue.Str("a\uDC00"));
        refusedEverywhere(new JsonValue.Str("\uFFFF"));
        refusedEverywhere(new JsonValue.Str("\uFDD0"));
        refusedEverywhere(new JsonValue.Str("\uDBFF\uDFFF"));
        refusedEverywhere(obj("\uD800", new JsonValue.Null()));
        refusedEverywhere(new JsonValue.Arr(List.of(obj("ok", new JsonValue.Str("\uFFFE")))));

        refusedEverywhere(nested(33));
        JsonWriter.wire(nested(32));
        JsonWriter.file(nested(32));

        // 262 145 bytes, its quotes included: past the wire limit, but well within a file's
        JsonValue large = new JsonValue.Str("a".repeat(JsonReader.WIRE_BYTES - 1));
        refusedOnTheWire(large);
        JsonWriter.file(large);
        JsonWriter.wire(new JsonValue.Str("a".repeat(JsonReader.WIRE_BYTES - 2)));
        // the limit counts UTF-8 bytes: U+00E9 is two, so this is 262 146 bytes in 131 074 characters
        refusedOnTheWire(new JsonValue.Str("\u00e9".repeat(JsonReader.WIRE_BYTES / 2)));
        // a file ends in a newline, so this string's file, its quotes and newline included, is one byte past the limit
        MalformedJsonException e = assertThrows(MalformedJsonException.class,
                () -> JsonWriter.file(new JsonValue.Str("a".repeat(JsonReader.FILE_BYTES - 2))));
        assertEquals(Step.WRITE, e.step());
        JsonWriter.file(new JsonValue.Str("a".repeat(JsonReader.FILE_BYTES - 3)));
    }

    @Test
    void fileWritesTheFileFormat() {
        JsonValue v = obj(
                "b", new JsonValue.Arr(List.of(new JsonValue.Int(1), obj())),
                "a", new JsonValue.Str("\u00e9"));
        assertEquals("{\n  \"a\": \"\u00e9\",\n  \"b\": [\n    1,\n    {}\n  ]\n}\n", JsonWriter.file(v));
        assertEquals("[]\n", JsonWriter.file(new JsonValue.Arr(List.of())));
        assertEquals("\"\\u0001\"\n", JsonWriter.file(new JsonValue.Str("\u0001")));
    }
}
