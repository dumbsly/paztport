// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.Json;

/**
 * The current stamp. {@code rcv} is signed, so a stamp is only good for the receiver it names and a captured one
 * cannot be replayed at another service. Fields are joined with {@code |}, so a field holding one (or a lone
 * surrogate, which has no UTF-8 bytes) would let two stamps share signed bytes; {@link #sign} refuses both.
 */
public record StampV3(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
        String infl, String prev, String sig) implements RecordedStamp {

    private static final long MAX_SAFE_TS = (1L << 53) - 1;

    /** Signs a stamp; throws {@link IllegalArgumentException} if a signed field holds the delimiter or a lone surrogate, or ts is outside the safe-integer range. */
    public static StampV3 sign(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
            String infl, String prev, PrivateKey key) {
        if (Math.abs(ts) > MAX_SAFE_TS) {
            throw new IllegalArgumentException("stamp ts must be within +/-(2^53-1)");
        }
        byte[] bytes = join("3", svc, inst, rid, Long.toString(ts), sess, rcv, bind, infl, prev);
        return new StampV3(svc, inst, rid, ts, sess, rcv, bind, infl, prev,
                Base64Url.encode(Crypto.sign(key, bytes)));
    }

    @Override
    public byte[] signingBytes() {
        return join("3", svc, inst, rid, Long.toString(ts), sess, rcv, bind, infl, prev);
    }

    @Override
    public String rcvOrNull() {
        return rcv;
    }

    /** The wire form: {@code "v": 3} then the fields in the order the wire format shows. */
    public String toJson() {
        return Json.text(tree());
    }

    ObjectNode tree() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("v", 3);
        o.put("svc", svc);
        o.put("inst", inst);
        o.put("rid", rid);
        o.put("ts", ts);
        o.put("sess", sess);
        o.put("rcv", rcv);
        o.put("bind", bind);
        o.put("infl", infl);
        o.put("prev", prev);
        o.put("sig", sig);
        return o;
    }

    /** Joins signed values with the delimiter; shared with v2. Null, a delimiter or a lone surrogate throws. */
    static byte[] join(String... values) {
        for (String s : values) {
            if (s == null || s.indexOf('|') >= 0 || !Text.isWellFormed(s)) {
                throw new IllegalArgumentException("stamp field must be a string without '|' or a lone surrogate");
            }
        }
        return String.join("|", values).getBytes(StandardCharsets.UTF_8);
    }
}
