// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * The current stamp. {@code rcv} is signed, so a stamp is only good for the receiver it names and a captured one
 * cannot be replayed at another service. Fields are joined with {@code |}, so a field holding one (or a lone
 * surrogate, which has no UTF-8 bytes) would let two stamps share signed bytes; {@link #sign} refuses both, and a
 * noncharacter too, which no reader reads.
 */
public record Stamp(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
        String infl, String prev, String sig) {

    /**
     * Signs a stamp; throws {@link IllegalArgumentException} if a signed field holds the delimiter, a lone surrogate
     * or a noncharacter, or ts is outside [0, 2^53 &minus; 1].
     */
    public static Stamp sign(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
            String infl, String prev, PrivateKey key) {
        if (!JsonIntegers.inRange(ts)) {
            throw new IllegalArgumentException("stamp ts must be an integer in [0, 2^53 - 1]");
        }
        byte[] bytes = join("3", svc, inst, rid, Long.toString(ts), sess, rcv, bind, infl, prev);
        return new Stamp(svc, inst, rid, ts, sess, rcv, bind, infl, prev,
                Base64Url.encode(Crypto.sign(key, bytes)));
    }

    /** The bytes the stamp's signature covers. */
    public byte[] signingBytes() {
        return join("3", svc, inst, rid, Long.toString(ts), sess, rcv, bind, infl, prev);
    }

    /** The wire form: the object's JCS text, its members in JCS order. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The stamp as a JSON value. */
    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("v", new JsonValue.Int(3));
        o.put("svc", new JsonValue.Str(svc));
        o.put("inst", new JsonValue.Str(inst));
        o.put("rid", new JsonValue.Str(rid));
        o.put("ts", new JsonValue.Int(ts));
        o.put("sess", new JsonValue.Str(sess));
        o.put("rcv", new JsonValue.Str(rcv));
        o.put("bind", new JsonValue.Str(bind));
        o.put("infl", new JsonValue.Str(infl));
        o.put("prev", new JsonValue.Str(prev));
        o.put("sig", new JsonValue.Str(sig));
        return new JsonValue.Obj(o);
    }

    /** Joins signed values with the delimiter; null, a delimiter, a lone surrogate or a noncharacter throws. */
    static byte[] join(String... values) {
        for (String s : values) {
            if (s == null || s.indexOf('|') >= 0 || !Text.isWellFormed(s) || Text.hasNoncharacter(s)) {
                throw new IllegalArgumentException(
                        "stamp field must be a string without '|', a lone surrogate or a noncharacter");
            }
        }
        return String.join("|", values).getBytes(StandardCharsets.UTF_8);
    }
}
