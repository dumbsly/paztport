// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import org.paztport.core.internal.JcsWriter;
import org.paztport.core.internal.Json;

/**
 * RFC 8785 JSON Canonicalization Scheme over JSON text, by the rules {@link JcsWriter} states: only objects, arrays,
 * strings, booleans, null and integers within &plusmn;(2^53&minus;1). Text that is not exactly one JSON value, or
 * that holds anything else (a fraction, {@code 1.0}, a larger integer, a lone surrogate), throws
 * {@link IllegalArgumentException}, because the TypeScript SDK would print it differently and the two would sign
 * different bytes.
 */
public final class Jcs {

    private Jcs() {
    }

    public static String canonicalize(String json) {
        return JcsWriter.canonicalize(Json.tree(json));
    }

    public static byte[] bytes(String json) {
        return JcsWriter.bytes(Json.tree(json));
    }
}
