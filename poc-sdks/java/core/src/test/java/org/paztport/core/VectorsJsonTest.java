// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * Replays {@code spec/vectors/json.json}, which the TypeScript SDK also reads: one test per case of {@code wire},
 * {@code file} and {@code fileFormat}. The {@code jcs} section is not replayed: it is hashed content, which belongs
 * to the MCP profile, and this SDK does not implement it. The file's own structure is read with Jackson, only to
 * find each case and build its expected value; every input reaches the SDK as bytes.
 */
class VectorsJsonTest {

    static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("json.json");
    }

    /** A case's input: the UTF-8 of {@code utf8}, the bytes of {@code hex}, or the text {@code build} spells out. */
    private static byte[] input(JsonNode c) {
        List<String> given = new ArrayList<>();
        c.fieldNames().forEachRemaining(n -> {
            if (List.of("utf8", "hex", "build").contains(n)) {
                given.add(n);
            }
        });
        assertEquals(1, given.size(), "one input");
        return switch (given.get(0)) {
            case "utf8" -> utf8(c.get("utf8").textValue());
            case "hex" -> HexFormat.of().parseHex(c.get("hex").textValue());
            default -> {
                JsonNode b = c.get("build");
                yield utf8(b.get("head").textValue() + b.get("repeat").textValue().repeat(b.get("times").intValue())
                        + b.get("tail").textValue());
            }
        };
    }

    private static byte[] utf8(String s) {
        assertTrue(Text.isWellFormed(s), "a utf8 input has a UTF-8 form");
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static Stream<DynamicTest> cases(String section, Case check) {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : vectors.get(section)) {
            tests.add(DynamicTest.dynamicTest(section + ": " + c.get("name").textValue(), () -> check.run(c)));
        }
        assertFalse(tests.isEmpty(), section + " has its cases");
        return tests.stream();
    }

    /** A value as plain data that keeps an object's names in the order it holds them, which {@code equals} ignores. */
    private static Object ordered(JsonValue v) {
        return switch (v) {
            case JsonValue.Obj o -> {
                List<Object> members = new ArrayList<>();
                for (String name : List.copyOf(o.names())) {
                    members.add(List.of(name, ordered(o.get(name))));
                }
                yield members;
            }
            case JsonValue.Arr a -> a.items().stream().map(VectorsJsonTest::ordered).toList();
            default -> v;
        };
    }

    private static void assertSameValue(JsonNode expected, JsonValue read) {
        JsonValue want = Vectors.value(expected);
        assertEquals(want, read);
        assertEquals(ordered(want), ordered(read), "names in source order");
    }

    /** The step a refused case names, and the step the reader's exception gives. */
    private static void assertRefused(JsonNode c, Executable read) {
        assertEquals("REFUSED", c.get("expected").textValue());
        MalformedJsonException e = assertThrows(MalformedJsonException.class, read);
        assertEquals(c.get("step").textValue(), e.step().name().toLowerCase(Locale.ROOT));
    }

    private interface Case {
        void run(JsonNode c) throws Exception;
    }

    @Test
    void theLimitsAreTheReaders() {
        JsonNode limits = vectors.get("limits");
        assertEquals(JsonReader.WIRE_BYTES, limits.get("wireBytes").intValue());
        assertEquals(JsonReader.TOKEN_TEXT, limits.get("tokenText").intValue());
        assertEquals(JsonReader.FILE_BYTES, limits.get("fileBytes").intValue());
        assertEquals(JsonReader.MAX_DEPTH, limits.get("depth").intValue());
    }

    /** Each case's bytes read as a base64url token, and an object read writes back as the same bytes. */
    @TestFactory
    Stream<DynamicTest> wire() {
        return cases("wire", c -> {
            byte[] bytes = input(c);
            String token = Base64Url.encode(bytes);
            if (c.get("expected").textValue().equals("OK")) {
                JsonValue read = JsonReader.token(token);
                if (c.has("value")) {
                    assertSameValue(c.get("value"), read);
                }
                assertArrayEquals(bytes, JsonWriter.wire(read));
            } else {
                assertRefused(c, () -> JsonReader.token(token));
            }
        });
    }

    /** Each case's bytes read as a file. */
    @TestFactory
    Stream<DynamicTest> file() {
        return cases("file", c -> {
            byte[] bytes = input(c);
            if (c.get("expected").textValue().equals("OK")) {
                JsonValue read = JsonReader.file(bytes);
                if (c.has("value")) {
                    assertSameValue(c.get("value"), read);
                }
            } else {
                assertRefused(c, () -> JsonReader.file(bytes));
            }
        });
    }

    /** Each value printed as a file gives the file exactly, and the file reads back as the value. */
    @TestFactory
    Stream<DynamicTest> fileFormat() {
        return cases("fileFormat", c -> {
            JsonValue value = Vectors.value(c.get("value"));
            String file = c.get("file").textValue();
            assertEquals(file, JsonWriter.file(value));
            assertEquals(value, JsonReader.file(utf8(file)));
        });
    }
}
