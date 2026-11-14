// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * A version 4 stamp (spec wire.md, Stamps): one hop's signature over what it sent, linked to the stamp before it.
 * {@code rcv} is signed, so a stamp is only good for the receiver it names and a captured one cannot be replayed at
 * another service. {@code ext} commits to the signer's block ({@link Block#commit}). The signature covers the JCS
 * bytes of the stamp's other ten members, which escape every string, so no field needs a rule against a delimiter;
 * a lone surrogate or a noncharacter, which no reader reads, is never signed.
 */
public record Stamp(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
        String ext, String prev, String sig) {

    /** The stamp version this SDK signs and reads (spec wire.md, Stamps): the one place the number is written. */
    public static final int VERSION = 4;

    /** The stamp's domain prefix (spec wire.md, Encodings), so no other signed message reads as a stamp. */
    private static final byte[] PREFIX = "paztport-stamp\n".getBytes(StandardCharsets.UTF_8);

    /**
     * Signs a stamp.
     *
     * @throws IllegalArgumentException a field that is null or holds a lone surrogate or a noncharacter, or a
     *     {@code ts} outside [0, 2^53 &minus; 1]
     */
    public static Stamp sign(String svc, String inst, String rid, long ts, String sess, String rcv, String bind,
            String ext, String prev, PrivateKey key) {
        if (!JsonIntegers.inRange(ts)) {
            throw new IllegalArgumentException("stamp ts must be an integer in [0, 2^53 - 1]");
        }
        Stamp unsigned = new Stamp(svc, inst, rid, ts, sess, rcv, bind, ext, prev, "");
        return new Stamp(svc, inst, rid, ts, sess, rcv, bind, ext, prev,
                Base64Url.encode(Crypto.sign(key, unsigned.signingBytes())));
    }

    /**
     * The bytes the stamp's signature covers: {@code utf8("paztport-stamp\n")} then the JCS bytes of the ten members
     * other than {@code sig}, {@code v} included (spec wire.md, Fields and signed bytes).
     *
     * @throws IllegalArgumentException a field that is null or holds a lone surrogate or a noncharacter, or a
     *     {@code ts} that is not a protocol integer
     */
    public byte[] signingBytes() {
        Map<String, JsonValue> members = members();
        members.remove("sig");
        // the writer refuses a lone surrogate and a noncharacter, as the reader does, so neither is ever signed
        byte[] json = JsonWriter.wire(new JsonValue.Obj(members));
        byte[] out = new byte[PREFIX.length + json.length];
        System.arraycopy(PREFIX, 0, out, 0, PREFIX.length);
        System.arraycopy(json, 0, out, PREFIX.length, json.length);
        return out;
    }

    /** The wire form: the object's JCS text, its members in JCS order. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The stamp as a JSON value. */
    JsonValue.Obj tree() {
        return new JsonValue.Obj(members());
    }

    /** The stamp's eleven members, each checked for null so a missing field names itself. */
    private Map<String, JsonValue> members() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("v", new JsonValue.Int(VERSION));
        o.put("svc", text("svc", svc));
        o.put("inst", text("inst", inst));
        o.put("rid", text("rid", rid));
        o.put("ts", new JsonValue.Int(ts));
        o.put("sess", text("sess", sess));
        o.put("rcv", text("rcv", rcv));
        o.put("bind", text("bind", bind));
        o.put("ext", text("ext", ext));
        o.put("prev", text("prev", prev));
        o.put("sig", text("sig", sig));
        return o;
    }

    private static JsonValue.Str text(String field, String value) {
        if (value == null) {
            throw new IllegalArgumentException("stamp field " + field + " is null");
        }
        return new JsonValue.Str(value);
    }
}
