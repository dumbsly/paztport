// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import org.paztport.core.internal.JsonWriter;

/**
 * A chain's key in the replay cache (spec verification.md, Freshness and replay): the JCS text of an array of
 * strings. A key is the verifier's own text and never travels, so it is written as hashed content is, with a
 * noncharacter as itself (spec wire.md, Hashed content). JCS escapes every string and keeps the elements apart, so no
 * part needs a rule against a delimiter.
 */
public final class NonceKeys {

    private NonceKeys() {
    }

    /**
     * The JCS text of the array of parts, each written as RFC 8785 writes strings.
     *
     * @throws IllegalArgumentException a part that is null or holds a lone surrogate
     */
    public static String of(String... parts) {
        StringBuilder key = new StringBuilder("[");
        for (int i = 0; i < parts.length; i++) {
            if (parts[i] == null) {
                throw new IllegalArgumentException("nonce key: a part that is not a string");
            }
            if (i > 0) {
                key.append(',');
            }
            key.append(JsonWriter.quoted(parts[i], true));
        }
        return key.append(']').toString();
    }
}
