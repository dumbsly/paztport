// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.MalformedJsonException.Step;
import org.paztport.core.encoding.Text;

/**
 * Reads Paztport's objects from bytes by the spec's JSON reading steps: the size limit before anything is parsed,
 * then one pass over the bytes under the strict grammar (RFC 8259 within I-JSON, strict UTF-8 by RFC 3629, no lone
 * surrogate or noncharacter, no repeated name, protocol integers only, and the depth limit checked before each
 * descent, so recursion never goes deeper than {@link #MAX_DEPTH}), and for wire bytes the canonical-bytes check.
 * Every refusal is a {@link MalformedJsonException} naming its step. The object's schema is its own reader's.
 */
public final class JsonReader {

    /** The most wire bytes an object may be. */
    public static final int WIRE_BYTES = 256 * 1024;
    /** The most characters a base64url token may be: the unpadded length of {@link #WIRE_BYTES} bytes. */
    public static final int TOKEN_TEXT = 349_526;
    /** The most bytes a file may be. */
    public static final int FILE_BYTES = 1024 * 1024;
    /** The deepest a value may nest: {@code []} is one level and {@code [[]]} two. */
    public static final int MAX_DEPTH = 32;

    /** A protocol integer's most digits; 2^53 &minus; 1 has 16. */
    private static final int MAX_DIGITS = 16;

    private final byte[] in;
    private int pos;

    private JsonReader(byte[] in) {
        this.in = in;
    }

    /** Wire bytes: within {@link #WIRE_BYTES}, one value under the grammar, and exactly its canonical bytes. */
    public static JsonValue wire(byte[] bytes) {
        if (bytes.length > WIRE_BYTES) {
            throw new MalformedJsonException(Step.SIZE, "wire bytes past " + WIRE_BYTES + " bytes");
        }
        JsonValue value = new JsonReader(bytes).document();
        if (!Arrays.equals(JsonWriter.wire(value), bytes)) {
            throw new MalformedJsonException(Step.CANONICAL, "wire bytes that are not canonical");
        }
        return value;
    }

    /**
     * A base64url token's object. Its text is measured before it is decoded, so no more than {@link #WIRE_BYTES}
     * bytes are ever decoded; text that does not decode is refused as a parse.
     */
    public static JsonValue token(String base64url) {
        if (base64url.length() > TOKEN_TEXT) {
            throw new MalformedJsonException(Step.SIZE, "a token past " + TOKEN_TEXT + " characters");
        }
        byte[] bytes;
        try {
            bytes = Base64Url.decode(base64url);
        } catch (IllegalArgumentException e) {
            throw new MalformedJsonException(Step.PARSE, "a token that is not base64url");
        }
        return wire(bytes);
    }

    /**
     * JSON text read as the wire bytes of its UTF-8, for an API that takes text. A string longer than the limit
     * has more UTF-8 bytes than that, so it is refused before it is encoded; one holding a lone surrogate has no
     * UTF-8 form and is refused as a parse.
     */
    public static JsonValue wireText(String json) {
        if (json.length() > WIRE_BYTES) {
            throw new MalformedJsonException(Step.SIZE, "wire bytes past " + WIRE_BYTES + " bytes");
        }
        if (!Text.isWellFormed(json)) {
            throw new MalformedJsonException(Step.PARSE, "text holding a lone surrogate");
        }
        return wire(json.getBytes(StandardCharsets.UTF_8));
    }

    /** A file: within {@link #FILE_BYTES} and one value under the grammar, in any member order and whitespace. */
    public static JsonValue file(byte[] bytes) {
        if (bytes.length > FILE_BYTES) {
            throw new MalformedJsonException(Step.SIZE, "a file past " + FILE_BYTES + " bytes");
        }
        return new JsonReader(bytes).document();
    }

    private JsonValue document() {
        whitespace();
        JsonValue value = value(0);
        whitespace();
        if (pos < in.length) {
            throw refuse("more after the value");
        }
        return value;
    }

    /** The value at {@code pos}, inside {@code depth} arrays and objects. */
    private JsonValue value(int depth) {
        if (pos >= in.length) {
            throw refuse("no value");
        }
        return switch (in[pos]) {
            case '{' -> object(descend(depth));
            case '[' -> array(descend(depth));
            case '"' -> new JsonValue.Str(string());
            case 't' -> literal("true", new JsonValue.Bool(true));
            case 'f' -> literal("false", new JsonValue.Bool(false));
            case 'n' -> literal("null", new JsonValue.Null());
            case '-' -> throw refuse("a negative number");
            default -> {
                if (in[pos] >= '0' && in[pos] <= '9') {
                    yield integer();
                }
                throw refuse("no value");
            }
        };
    }

    private int descend(int depth) {
        if (depth == MAX_DEPTH) {
            throw refuse("nested deeper than " + MAX_DEPTH);
        }
        pos++;
        return depth + 1;
    }

    private JsonValue object(int depth) {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        whitespace();
        if (next('}')) {
            return new JsonValue.Obj(members);
        }
        do {
            whitespace();
            if (pos >= in.length || in[pos] != '"') {
                throw refuse("no member name");
            }
            int at = pos;
            String name = string();
            if (members.containsKey(name)) {
                pos = at;
                throw refuse("a repeated member name");
            }
            whitespace();
            expect(':');
            whitespace();
            members.put(name, value(depth));
            whitespace();
        } while (next(','));
        expect('}');
        return new JsonValue.Obj(members);
    }

    private JsonValue array(int depth) {
        List<JsonValue> items = new ArrayList<>();
        whitespace();
        if (next(']')) {
            return new JsonValue.Arr(items);
        }
        do {
            whitespace();
            items.add(value(depth));
            whitespace();
        } while (next(','));
        expect(']');
        return new JsonValue.Arr(items);
    }

    private JsonValue literal(String word, JsonValue value) {
        for (int i = 0; i < word.length(); i++) {
            if (pos + i >= in.length || in[pos + i] != word.charAt(i)) {
                throw refuse("no value");
            }
        }
        pos += word.length();
        return value;
    }

    /**
     * A protocol integer, decided from its text before any value is built: no fraction or exponent, no leading
     * zero, and at most 16 digits, so a long number is refused at its seventeenth digit.
     */
    private JsonValue integer() {
        int start = pos;
        long value = 0;
        while (pos < in.length && in[pos] >= '0' && in[pos] <= '9') {
            if (pos - start == MAX_DIGITS) {
                throw refuse("a number of more than " + MAX_DIGITS + " digits");
            }
            value = value * 10 + (in[pos] - '0');
            pos++;
        }
        if (in[start] == '0' && pos - start > 1) {
            pos = start;
            throw refuse("a number with a leading zero");
        }
        if (pos < in.length && (in[pos] == '.' || in[pos] == 'e' || in[pos] == 'E')) {
            throw refuse("a number that is not an integer");
        }
        if (value > JsonValue.Int.MAX) {
            pos = start;
            throw refuse("a number past 2^53 - 1");
        }
        return new JsonValue.Int(value);
    }

    /** The string at {@code pos}, its opening quote included, unescaped and checked character by character. */
    private String string() {
        pos++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= in.length) {
                throw refuse("a string with no end");
            }
            int b = in[pos] & 0xff;
            if (b == '"') {
                pos++;
                return sb.toString();
            } else if (b == '\\') {
                sb.appendCodePoint(character(escape()));
            } else if (b < 0x20) {
                throw refuse("a control character in a string");
            } else if (b < 0x80) {
                sb.append((char) b);
                pos++;
            } else {
                sb.appendCodePoint(character(utf8()));
            }
        }
    }

    /** The code point an escape stands for, a surrogate pair's two escapes read as one. */
    private int escape() {
        int at = pos;
        pos++;
        if (pos >= in.length) {
            throw refuse("a string with no end");
        }
        int c = switch (in[pos]) {
            case '"' -> '"';
            case '\\' -> '\\';
            case '/' -> '/';
            case 'b' -> '\b';
            case 'f' -> '\f';
            case 'n' -> '\n';
            case 'r' -> '\r';
            case 't' -> '\t';
            case 'u' -> -1;
            default -> throw refuse("an escape JSON does not define");
        };
        pos++;
        if (c >= 0) {
            return c;
        }
        int unit = hex4();
        if (Character.isLowSurrogate((char) unit)) {
            pos = at;
            throw refuse("a lone surrogate");
        }
        if (!Character.isHighSurrogate((char) unit)) {
            return unit;
        }
        if (pos + 1 < in.length && in[pos] == '\\' && in[pos + 1] == 'u') {
            pos += 2;
            int low = hex4();
            if (Character.isLowSurrogate((char) low)) {
                return Character.toCodePoint((char) unit, (char) low);
            }
        }
        pos = at;
        throw refuse("a lone surrogate");
    }

    private int hex4() {
        int unit = 0;
        for (int i = 0; i < 4; i++) {
            int d = pos < in.length ? Character.digit(in[pos], 16) : -1;
            if (d < 0) {
                throw refuse("an escape with fewer than four hex digits");
            }
            unit = unit << 4 | d;
            pos++;
        }
        return unit;
    }

    /**
     * The code point of the UTF-8 sequence at {@code pos}, by RFC 3629's table, which admits no overlong form, no
     * surrogate and nothing past U+10FFFF: each lead byte fixes the sequence's length and its second byte's range.
     */
    private int utf8() {
        int lead = in[pos] & 0xff;
        int length;
        int min;
        int max;
        if (lead >= 0xc2 && lead <= 0xdf) {
            length = 2;
            min = 0x80;
            max = 0xbf;
        } else if (lead == 0xe0) {
            length = 3;
            min = 0xa0;
            max = 0xbf;
        } else if (lead == 0xed) {
            length = 3;
            min = 0x80;
            max = 0x9f;
        } else if (lead >= 0xe1 && lead <= 0xef) {
            length = 3;
            min = 0x80;
            max = 0xbf;
        } else if (lead == 0xf0) {
            length = 4;
            min = 0x90;
            max = 0xbf;
        } else if (lead >= 0xf1 && lead <= 0xf3) {
            length = 4;
            min = 0x80;
            max = 0xbf;
        } else if (lead == 0xf4) {
            length = 4;
            min = 0x80;
            max = 0x8f;
        } else {
            throw refuse("a byte that starts no UTF-8 sequence");
        }
        if (pos + length > in.length) {
            throw refuse("a UTF-8 sequence cut short");
        }
        int cp = lead & (0x7f >> length);
        for (int i = 1; i < length; i++) {
            int b = in[pos + i] & 0xff;
            if (i == 1 ? b < min || b > max : b < 0x80 || b > 0xbf) {
                throw refuse("an invalid UTF-8 sequence");
            }
            cp = cp << 6 | b & 0x3f;
        }
        pos += length;
        return cp;
    }

    /** The code point, unless it is a noncharacter. */
    private int character(int cp) {
        if (Text.isNoncharacter(cp)) {
            throw refuse("a noncharacter");
        }
        return cp;
    }

    private boolean next(char c) {
        if (pos < in.length && in[pos] == c) {
            pos++;
            return true;
        }
        return false;
    }

    private void expect(char c) {
        if (!next(c)) {
            throw refuse(pos < in.length ? "no '" + c + "'" : "an unexpected end");
        }
    }

    private void whitespace() {
        while (pos < in.length && (in[pos] == ' ' || in[pos] == '\t' || in[pos] == '\n' || in[pos] == '\r')) {
            pos++;
        }
    }

    private MalformedJsonException refuse(String what) {
        return new MalformedJsonException(Step.PARSE, "JSON refused: " + what + ", at byte " + pos);
    }
}
