// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.verify.ReasonCode;

/**
 * Reads a chain off the wire, strictly: the first two checks of the live order. It works on the Jackson tree
 * rather than binding to records so a wrong type or an out-of-range integer is seen as it is, and it never
 * throws; every malformed input comes back as a {@link ParsedChain} carrying a reason.
 */
public final class Chains {

    private static final List<String> V3_STRINGS = List.of("svc", "inst", "rid", "sess", "rcv", "bind", "infl", "prev");
    private static final List<String> V2_STRINGS = List.of("svc", "inst", "rid", "sess", "bind", "infl", "prev");
    private static final Set<Integer> VERSIONS = Set.of(2, 3);

    private Chains() {
    }

    /**
     * Check 1: the field rules (all stamps one version, exact types, no lone surrogate, canonical {@code sig}),
     * all {@code CHAIN_MISSING}. Check 2: no signed field holds {@code |}, {@code BAD_SIGNATURE}. A v2 chain is
     * accepted, as legacy, only when {@code acceptLegacy} is set.
     */
    public static ParsedChain parse(JsonNode stamps, boolean acceptLegacy) {
        if (stamps == null || !stamps.isArray() || stamps.isEmpty()) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
        }
        Integer version = version(stamps.get(0));
        if (version == null || (version == 2 && !acceptLegacy)) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
        }
        List<RecordedStamp> out = new ArrayList<>();
        for (JsonNode item : stamps) {
            RecordedStamp s = stamp(item, version);
            if (s == null) {
                return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
            }
            out.add(s);
        }
        for (RecordedStamp s : out) {
            try {
                s.signingBytes();
            } catch (IllegalArgumentException e) {
                return ParsedChain.fail(ReasonCode.BAD_SIGNATURE);
            }
        }
        return new ParsedChain(out, version == 2, null);
    }

    private static Integer version(JsonNode item) {
        if (item == null || !item.isObject()) {
            return null;
        }
        Long v = JsonIntegers.safeInteger(item.get("v"));
        return v != null && VERSIONS.contains(v.intValue()) && v == v.intValue() ? v.intValue() : null;
    }

    /** One stamp of the given version, or null if any field breaks the rules. */
    private static RecordedStamp stamp(JsonNode item, int version) {
        if (item == null || !item.isObject()) {
            return null;
        }
        Integer v = version(item);
        Long ts = JsonIntegers.safeInteger(item.get("ts"));
        if (v == null || v != version || ts == null) {
            return null;
        }
        for (String f : version == 3 ? V3_STRINGS : V2_STRINGS) {
            if (str(item, f) == null) {
                return null;
            }
        }
        String sig = str(item, "sig");
        if (sig == null || !canonical(sig)) {
            return null;
        }
        if (version == 3) {
            return new StampV3(str(item, "svc"), str(item, "inst"), str(item, "rid"), ts, str(item, "sess"),
                    str(item, "rcv"), str(item, "bind"), str(item, "infl"), str(item, "prev"), sig);
        }
        return new StampV2(str(item, "svc"), str(item, "inst"), str(item, "rid"), ts, str(item, "sess"),
                str(item, "bind"), str(item, "infl"), str(item, "prev"), sig);
    }

    /** The field as a well-formed string, or null if absent, not a string, or holding a lone surrogate. */
    private static String str(JsonNode o, String name) {
        JsonNode n = o.get(name);
        if (n == null || !n.isTextual() || !Text.isWellFormed(n.textValue())) {
            return null;
        }
        return n.textValue();
    }

    /** True when the text decodes as base64url and encodes back to itself. */
    private static boolean canonical(String sig) {
        try {
            return Base64Url.encode(Base64Url.decode(sig)).equals(sig);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
