// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import com.fasterxml.jackson.databind.JsonNode;
import org.paztport.core.internal.JcsWriter;

/** RFC 8785 JSON Canonicalization Scheme, by the rules {@link JcsWriter} states. */
public final class Jcs {

    private Jcs() {
    }

    public static String canonicalize(JsonNode node) {
        return JcsWriter.canonicalize(node);
    }

    public static byte[] bytes(JsonNode node) {
        return JcsWriter.bytes(node);
    }
}
