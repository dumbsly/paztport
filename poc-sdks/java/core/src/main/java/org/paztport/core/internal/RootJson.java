// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.databind.JsonNode;
import org.paztport.core.policy.SignedRoot;

/**
 * A signed root's reader over a Jackson tree, by the rules {@link SignedRoot#parse} states. Here rather than in
 * {@link SignedRoot} because the session handshake carries roots inside its own messages, and so reads them from a
 * tree it already holds, in another package.
 */
public final class RootJson {

    private RootJson() {
    }

    /** {@link SignedRoot#parse}'s rules over a tree; throws {@link IllegalArgumentException} as it does. */
    public static SignedRoot read(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("a signed root must be a JSON object");
        }
        Long notAfter = null;
        if (node.has("notAfter")) {
            notAfter = JsonIntegers.notAfter(node.get("notAfter"));
            if (notAfter == null) {
                throw new IllegalArgumentException("signed root notAfter must be an integer in [0, 2^53 - 1]");
            }
        }
        return new SignedRoot(text(node, "rootId"), text(node, "root"), text(node, "sig"), notAfter);
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || !v.isTextual()) {
            throw new IllegalArgumentException("signed root " + field + " must be a string");
        }
        return v.textValue();
    }
}
