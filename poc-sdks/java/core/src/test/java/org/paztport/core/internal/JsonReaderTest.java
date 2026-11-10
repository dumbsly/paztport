// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.MalformedJsonException.Step;

class JsonReaderTest {

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static MalformedJsonException refused(Step step, Executable read) {
        MalformedJsonException e = assertThrows(MalformedJsonException.class, read);
        assertEquals(step, e.step(), e.getMessage());
        return e;
    }

    private static JsonValue.Obj obj(Object... nameThenValue) {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        for (int i = 0; i < nameThenValue.length; i += 2) {
            members.put((String) nameThenValue[i], (JsonValue) nameThenValue[i + 1]);
        }
        return new JsonValue.Obj(members);
    }

    @Test
    void readsWhatItWrites() {
        JsonValue v = obj(
                "\uFB33", new JsonValue.Int(1),
                "\uD83D\uDE00", new JsonValue.Int(0),
                "s", new JsonValue.Str("\"\\\b\f\n\r\t\u0000\u001f/\u007f\u00e9\u2028\uD83D\uDE00"),
                "list", new JsonValue.Arr(List.of(new JsonValue.Bool(true), new JsonValue.Bool(false),
                        new JsonValue.Null(), new JsonValue.Int((1L << 53) - 1), obj(), new JsonValue.Arr(List.of()))));

        assertEquals(v, JsonReader.wire(JsonWriter.wire(v)));
        assertEquals(v, JsonReader.token(JsonWriter.token(v)));
        assertEquals(v, JsonReader.wireText(JsonWriter.text(v)));
        assertEquals(v, JsonReader.file(utf8(JsonWriter.file(v))));
    }

    @Test
    void readsMembersInTheOrderTheyCome() {
        JsonValue.Obj o = (JsonValue.Obj) JsonReader.file(utf8("{\"b\":1, \"a\":2, \"c\":3}"));
        assertEquals(List.of("b", "a", "c"), List.copyOf(o.names()));
    }

    @Test
    void refusesHostileSizesAtTheirLimit() {
        refused(Step.SIZE, () -> JsonReader.token("A".repeat(10 * 1024 * 1024)));
        // text that would not decode, so only a length check before decoding refuses it at SIZE
        refused(Step.SIZE, () -> JsonReader.token("*".repeat(JsonReader.TOKEN_TEXT + 1)));
        byte[] atLimit = utf8("\"" + "a".repeat(JsonReader.WIRE_BYTES - 2) + "\"");
        assertEquals(new JsonValue.Str("a".repeat(JsonReader.WIRE_BYTES - 2)),
                JsonReader.token(Base64Url.encode(atLimit)));

        byte[] pastLimit = new byte[JsonReader.WIRE_BYTES + 1];
        Arrays.fill(pastLimit, (byte) '[');
        refused(Step.SIZE, () -> JsonReader.wire(pastLimit));
        refused(Step.SIZE, () -> JsonReader.wireText("[".repeat(JsonReader.WIRE_BYTES + 1)));
        byte[] filePastLimit = new byte[JsonReader.FILE_BYTES + 1];
        Arrays.fill(filePastLimit, (byte) ' ');
        refused(Step.SIZE, () -> JsonReader.file(filePastLimit));

        byte[] nested = utf8("[".repeat(100_000));
        refused(Step.PARSE, () -> JsonReader.wire(nested));
        refused(Step.PARSE, () -> JsonReader.file(nested));
        String deep = "[".repeat(JsonReader.MAX_DEPTH) + "]".repeat(JsonReader.MAX_DEPTH);
        JsonReader.wire(utf8(deep));
        refused(Step.PARSE, () -> JsonReader.wire(utf8("[" + deep + "]")));

        MalformedJsonException e = refused(Step.PARSE, () -> JsonReader.wire(utf8("9".repeat(100_000))));
        assertTrue(e.getMessage().contains("more than 16 digits"), e.getMessage());
    }

    /**
     * Text the grammar refuses, refused at the parse both as wire bytes and as a file. As wire bytes, most of these
     * would also fail the canonical check, so only the file read shows the parse refusing them itself.
     */
    @Test
    void refusesWhatTheGrammarRefusesAtTheParse() {
        List<byte[]> refused = List.of(
                HexFormat.of().parseHex("22e0808022"), // the overlong form of U+0000
                HexFormat.of().parseHex("22e09fbf22"), // the overlong form of U+07FF
                HexFormat.of().parseHex("22f08fbfbd22"), // the overlong form of U+FFFD
                HexFormat.of().parseHex("22e282c022"), // a third byte that is not a continuation byte
                HexFormat.of().parseHex("22e282"), // a sequence cut short by the end of the input
                HexFormat.of().parseHex("220022"), // a raw U+0000
                utf8("\"\\udc00\""),
                utf8("\"\\ud800\\u0041\""),
                utf8("{}{}"),
                utf8("{} x"));
        for (byte[] bytes : refused) {
            refused(Step.PARSE, () -> JsonReader.wire(bytes));
            refused(Step.PARSE, () -> JsonReader.file(bytes));
        }
    }

    @Test
    void refusesANumberThatIsNotAProtocolIntegerByItsText() {
        MalformedJsonException fraction = refused(Step.PARSE, () -> JsonReader.file(utf8("1.0")));
        assertTrue(fraction.getMessage().contains("not an integer"), fraction.getMessage());
        MalformedJsonException negative = refused(Step.PARSE, () -> JsonReader.file(utf8("-1")));
        assertTrue(negative.getMessage().contains("negative"), negative.getMessage());
    }

    @Test
    void aRepeatedNameRefuses() {
        refused(Step.PARSE, () -> JsonReader.wire(utf8("{\"a\":1,\"a\":2}")));
        refused(Step.PARSE, () -> JsonReader.file(utf8("{\"a\":1,\"a\":2}")));
        refused(Step.PARSE, () -> JsonReader.file(utf8("{\"a\":1,\"\\u0061\":2}")));
        refused(Step.PARSE, () -> JsonReader.file(utf8("{\"a\":{\"x\":1},\"b\":2,\"a\":3}")));
        assertEquals(obj("a", obj("a", new JsonValue.Int(1))), JsonReader.wire(utf8("{\"a\":{\"a\":1}}")));
    }

    @Test
    void wireBytesMustBeCanonical() {
        refused(Step.CANONICAL, () -> JsonReader.wire(utf8("{\"b\":1,\"a\":2}")));
        refused(Step.CANONICAL, () -> JsonReader.wire(utf8("[1, 2]")));
        refused(Step.CANONICAL, () -> JsonReader.wire(utf8("\"\\u0041\"")));
        assertEquals(new JsonValue.Str("A"), JsonReader.file(utf8("\"\\u0041\"")));
    }

    @Test
    void aTokenThatDoesNotDecodeRefusesAtTheParse() {
        refused(Step.PARSE, () -> JsonReader.token("e30*"));
        refused(Step.PARSE, () -> JsonReader.token("e"));
    }

    @Test
    void wireTextRefusesALoneSurrogate() {
        refused(Step.PARSE, () -> JsonReader.wireText("\"\uD800\""));
        refused(Step.PARSE, () -> JsonReader.wireText("\"\uDC00x\""));
        assertEquals(new JsonValue.Str("\u00e9\uD83D\uDE00"), JsonReader.wireText("\"\u00e9\uD83D\uDE00\""));
    }

    @Test
    void callsNoJsonLibrary() throws IOException {
        Path dir = Path.of("src/main/java/org/paztport/core/internal");
        for (String name : List.of("JsonValue.java", "JsonReader.java", "JsonWriter.java")) {
            String source = Files.readString(dir.resolve(name), StandardCharsets.UTF_8);
            assertTrue(source.contains("package org.paztport.core.internal;"), name);
            for (String library : List.of("com.fasterxml", "tools.jackson", "com.google.gson")) {
                assertFalse(source.contains(library), name + " names " + library);
            }
        }
    }
}
