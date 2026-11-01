// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.verify.ReasonCode;

/**
 * Reads a chain off the wire, strictly: the first two checks of the live order. The chain's text must be the JCS
 * text of an array of stamps, each with exactly the stamp's members, and it never throws; every malformed input,
 * text that is not JSON included, comes back as a {@link ParsedChain} carrying a reason.
 */
public final class Chains {

    private static final Set<String> MEMBERS =
            Set.of("v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "infl", "prev", "sig");

    private Chains() {
    }

    /**
     * Check 1: the chain is read from its bytes (the JCS text of a non-empty array of stamps, each with exactly the
     * stamp's members, {@code v} 3, {@code ts} a protocol integer, the rest strings, {@code sig} canonical
     * base64url), all {@code CHAIN_MISSING}. Check 2: no signed field holds {@code |}, {@code BAD_SIGNATURE}. Null
     * is {@code CHAIN_MISSING} too.
     */
    public static ParsedChain parse(String json) {
        if (json == null) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
        }
        List<StampV3> out = new ArrayList<>();
        try {
            List<JsonValue> stamps = JsonFields.array(JsonReader.wireText(json));
            if (stamps.isEmpty()) {
                return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
            }
            for (JsonValue item : stamps) {
                out.add(stamp(item));
            }
        } catch (IllegalArgumentException e) {
            return ParsedChain.fail(ReasonCode.CHAIN_MISSING);
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
        return JsonWriter.text(tree(chain));
    }

    /** The chain as a JSON value, for the writers of this SDK; not API. */
    public static JsonValue.Arr tree(List<StampV3> chain) {
        return new JsonValue.Arr(chain.stream().map(s -> (JsonValue) s.tree()).toList());
    }

    /** One stamp by the stamp's schema; throws {@link IllegalArgumentException} naming the member it refuses. */
    private static StampV3 stamp(JsonValue item) {
        JsonValue.Obj o = JsonFields.object(item);
        JsonFields.exactly(o, MEMBERS, Set.of());
        if (JsonFields.integer(o, "v") != 3) {
            throw new IllegalArgumentException("member v is not 3");
        }
        String sig = JsonFields.string(o, "sig");
        Base64Url.decode(sig);
        return new StampV3(JsonFields.string(o, "svc"), JsonFields.string(o, "inst"), JsonFields.string(o, "rid"),
                JsonFields.integer(o, "ts"), JsonFields.string(o, "sess"), JsonFields.string(o, "rcv"),
                JsonFields.string(o, "bind"), JsonFields.string(o, "infl"), JsonFields.string(o, "prev"), sig);
    }
}
