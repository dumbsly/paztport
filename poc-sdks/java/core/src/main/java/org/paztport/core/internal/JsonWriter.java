// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.MalformedJsonException.Step;

/**
 * Writes a {@link JsonValue} as its canonical bytes (RFC 8785), or as a file in the spec's one file form, and
 * refuses whatever {@link JsonReader} would refuse: a string holding a lone surrogate or a noncharacter, a value
 * nested deeper than {@link JsonReader#MAX_DEPTH}, or output past its limit, which is {@link JsonReader#WIRE_BYTES}
 * for canonical bytes and {@link JsonReader#FILE_BYTES} for a file. It refuses the whole value with a
 * {@link MalformedJsonException} at {@link Step#WRITE}, and never writes a replacement in place of what it refuses.
 * The output is measured as it is written, so it stops at the first byte past the limit.
 */
public final class JsonWriter {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final StringBuilder out = new StringBuilder();
    private final int limit;
    private final boolean file;
    private int bytes;

    private JsonWriter(int limit, boolean file) {
        this.limit = limit;
        this.file = file;
    }

    /** The value's canonical bytes: its JCS text in UTF-8. */
    public static byte[] wire(JsonValue v) {
        // every string in the text was checked for lone surrogates as it was written
        return text(v).getBytes(StandardCharsets.UTF_8);
    }

    /** The value's JCS text, the text of {@link #wire}. */
    public static String text(JsonValue v) {
        JsonWriter w = new JsonWriter(JsonReader.WIRE_BYTES, false);
        w.value(v, 0);
        return w.out.toString();
    }

    /** The value's canonical bytes as a base64url token. */
    public static String token(JsonValue v) {
        return Base64Url.encode(wire(v));
    }

    /**
     * The value as a file: members in JCS order and strings escaped as JCS escapes them, two-space indentation with
     * one member or element per line, {@code ": "} after a name, {@code {}} and {@code []} for empty ones, and a
     * newline at the end.
     */
    public static String file(JsonValue v) {
        JsonWriter w = new JsonWriter(JsonReader.FILE_BYTES, true);
        w.value(v, 0);
        w.ascii("\n");
        return w.out.toString();
    }

    /** The value inside {@code depth} arrays and objects. */
    private void value(JsonValue v, int depth) {
        switch (v) {
            case JsonValue.Obj o -> object(o, depth);
            case JsonValue.Arr a -> array(a, depth);
            case JsonValue.Str s -> string(s.value());
            case JsonValue.Int i -> ascii(Long.toString(i.value()));
            case JsonValue.Bool b -> ascii(b.value() ? "true" : "false");
            case JsonValue.Null n -> ascii("null");
        }
    }

    private void object(JsonValue.Obj o, int depth) {
        descend(depth);
        if (o.members().isEmpty()) {
            ascii("{}");
            return;
        }
        // RFC 8785 (section 3.2.3) sorts names by their UTF-16 code units as unsigned numbers; a Java char is such a
        // unit, and compareTo compares the chars in turn
        List<String> names = new ArrayList<>(o.names());
        names.sort(String::compareTo);
        ascii("{");
        for (int i = 0; i < names.size(); i++) {
            if (i > 0) {
                ascii(",");
            }
            line(depth + 1);
            string(names.get(i));
            ascii(file ? ": " : ":");
            value(o.get(names.get(i)), depth + 1);
        }
        line(depth);
        ascii("}");
    }

    private void array(JsonValue.Arr a, int depth) {
        descend(depth);
        if (a.items().isEmpty()) {
            ascii("[]");
            return;
        }
        ascii("[");
        for (int i = 0; i < a.items().size(); i++) {
            if (i > 0) {
                ascii(",");
            }
            line(depth + 1);
            value(a.items().get(i), depth + 1);
        }
        line(depth);
        ascii("]");
    }

    private void descend(int depth) {
        if (depth == JsonReader.MAX_DEPTH) {
            throw refuse("a value nested deeper than " + JsonReader.MAX_DEPTH);
        }
    }

    /** In a file, a new line indented for {@code depth}; nothing in canonical bytes. */
    private void line(int depth) {
        if (file) {
            ascii("\n");
            ascii("  ".repeat(depth));
        }
    }

    /**
     * The string as RFC 8785 (section 3.2.2.2) escapes it: the two-character escapes for the characters that have
     * one, <code>&#92;u00xx</code> in lowercase hex for any other below U+0020, and every other character as itself.
     */
    private void string(String s) {
        ascii("\"");
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            int cp = c;
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                cp = Character.toCodePoint(c, s.charAt(i + 1));
            } else if (Character.isSurrogate(c)) {
                throw refuse("a string holding a lone surrogate");
            }
            if (JsonReader.isNoncharacter(cp)) {
                throw refuse("a string holding a noncharacter");
            }
            switch (cp) {
                case '"' -> ascii("\\\"");
                case '\\' -> ascii("\\\\");
                case '\b' -> ascii("\\b");
                case '\f' -> ascii("\\f");
                case '\n' -> ascii("\\n");
                case '\r' -> ascii("\\r");
                case '\t' -> ascii("\\t");
                default -> {
                    if (cp < 0x20) {
                        ascii("\\u00" + HEX[cp >> 4] + HEX[cp & 15]);
                    } else {
                        out.appendCodePoint(cp);
                        count(cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4);
                    }
                }
            }
            i += Character.charCount(cp);
        }
        ascii("\"");
    }

    private void ascii(String s) {
        out.append(s);
        count(s.length());
    }

    private void count(int n) {
        bytes += n;
        if (bytes > limit) {
            throw refuse("output past " + limit + " bytes");
        }
    }

    private static MalformedJsonException refuse(String what) {
        return new MalformedJsonException(Step.WRITE, "JSON not written: " + what);
    }
}
