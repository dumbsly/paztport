// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.Json;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.verify.ReasonCode;

/**
 * Reads a chain off the wire, strictly: the first two checks of the live order. It reads the JSON text into a tree
 * rather than binding it to records, so a wrong type or an out-of-range integer is seen as it is, and it never
 * throws; every malformed input, text that is not JSON included, comes back as a {@link ParsedChain} carrying a
 * reason.
 */
public final class Chains {

    private static final List<String> V3_STRINGS = List.of("svc", "inst", "rid", "sess", "rcv", "bind", "infl", "prev");

    private Chains() {
    }

    /**
     * Check 1: the field rules (every stamp {@code v: 3}, exact types, no lone surrogate, canonical {@code sig}),
     * all {@code CHAIN_MISSING}. Check 2: no signed field holds {@code |}, {@code BAD_SIGNATURE}. Null, or text
     * that is not one JSON value, is {@code CHAIN_MISSING} too.
     */
    public static ParsedChain parse(String json) {
        JsonNode stamps;
        try {
            stamps = Json.tree(json);
        } catch (IllegalArgumentException e) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
        }
        if (!stamps.isArray() || stamps.isEmpty()) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
        }
        List<StampV3> out = new ArrayList<>();
        for (JsonNode item : stamps) {
            StampV3 s = stamp(item);
            if (s == null) {
                return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
            }
            out.add(s);
        }
        for (StampV3 s : out) {
            try {
                s.signingBytes();
            } catch (IllegalArgumentException e) {
                return ParsedChain.fail(ReasonCode.BAD_SIGNATURE);
            }
        }
        return new ParsedChain(out, null);
    }

    /** The wire form of a chain: a JSON array of the stamps, origin first, each as {@link StampV3#toJson()}. */
    public static String toJson(List<StampV3> chain) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        chain.forEach(s -> a.add(s.tree()));
        return Json.text(a);
    }

    /** One stamp, or null if any field breaks the rules. */
    private static StampV3 stamp(JsonNode item) {
        if (item == null || !item.isObject()) {
            return null;
        }
        Long v = JsonIntegers.safeInteger(item.get("v"));
        Long ts = JsonIntegers.safeInteger(item.get("ts"));
        if (v == null || v != 3 || ts == null) {
            return null;
        }
        for (String f : V3_STRINGS) {
            if (str(item, f) == null) {
                return null;
            }
        }
        String sig = str(item, "sig");
        if (sig == null || !canonical(sig)) {
            return null;
        }
        return new StampV3(str(item, "svc"), str(item, "inst"), str(item, "rid"), ts, str(item, "sess"),
                str(item, "rcv"), str(item, "bind"), str(item, "infl"), str(item, "prev"), sig);
    }

    /** The field as a well-formed string, or null if absent, not a string, or holding a lone surrogate. */
    private static String str(JsonNode o, String name) {
        JsonNode n = o.get(name);
        if (n == null || !n.isTextual() || !Text.isWellFormed(n.textValue())) {
            return null;
        }
        return n.textValue();
    }

    /** True when the text is the canonical base64url encoding of some bytes. */
    private static boolean canonical(String sig) {
        try {
            Base64Url.decode(sig);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
