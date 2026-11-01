// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;
import org.paztport.core.policy.SignedRoot;

/**
 * A signed root's schema, by the rules {@link SignedRoot#parse} states. Here rather than in {@link SignedRoot}
 * because the session handshake carries roots inside its own messages, and so reads them from a value it already
 * holds, in another package.
 */
public final class RootJson {

    private static final Set<String> MEMBERS = Set.of("notAfter", "root", "rootId", "sig");

    private RootJson() {
    }

    /**
     * A root read: exactly {@code notAfter}, {@code root}, {@code rootId} and {@code sig}, the first an integer and
     * the others strings. Anything else throws {@link IllegalArgumentException} naming the member.
     */
    public static SignedRoot read(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        return new SignedRoot(JsonFields.string(o, "rootId"), JsonFields.string(o, "root"),
                JsonFields.string(o, "sig"), JsonFields.integer(o, "notAfter"));
    }

    /**
     * The root inside a session message, read from a Jackson tree: string {@code rootId}, {@code root} and
     * {@code sig}, and a {@code notAfter} judged by value; other members are ignored. Throws
     * {@link IllegalArgumentException} otherwise.
     */
    public static SignedRoot read(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("a signed root must be a JSON object");
        }
        Long notAfter = JsonIntegers.notAfter(node.get("notAfter"));
        if (notAfter == null) {
            throw new IllegalArgumentException("signed root notAfter must be an integer in [0, 2^53 - 1]");
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
