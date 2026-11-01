// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * RFC 8785 JSON Canonicalization Scheme over JSON text. The text is read by the file rules: one JSON value in any
 * member order and whitespace, within the file size and depth limits. Only objects, arrays, strings, booleans, null
 * and integers from 0 to 2^53&minus;1 are read. Text that is not exactly one such value (a fraction,
 * {@code 1.0}, a negative or larger integer, a lone surrogate, a second value after the first) throws
 * {@link MalformedJsonException}, because the TypeScript SDK would print it differently and the two would sign
 * different bytes. A {@code null} argument throws {@link IllegalArgumentException}.
 */
public final class Jcs {

    private Jcs() {
    }

    public static String canonicalize(String json) {
        return JsonWriter.text(read(json));
    }

    public static byte[] bytes(String json) {
        return JsonWriter.wire(read(json));
    }

    private static JsonValue read(String json) {
        if (json == null) {
            throw new IllegalArgumentException("jcs: no value");
        }
        return JsonReader.fileText(json);
    }
}
