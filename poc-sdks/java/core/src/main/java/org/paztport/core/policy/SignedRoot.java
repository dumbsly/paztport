// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.internal.RootJson;

/**
 * The pinned policy root: the Merkle root plus its version, signed by the policy key. Services pin this and reject
 * any proof that does not resolve to {@link #rootBytes()}, so a widened tree cannot be swapped in without the
 * policy key.
 *
 * <p>The policy key stays offline, so a root it once signed would otherwise allow its routes for ever, long after
 * the owner narrowed them. A root therefore carries {@code notAfter} (milliseconds since the epoch, inclusive) and
 * its signature covers {@code utf8("paztport-root\n") || JCS({notAfter, root, rootId})}, with {@code root} as its
 * base64url text. A root cannot stand in for a keyring, nor a keyring for it: each opens with its own prefix.
 *
 * <p>What the signer must have verified: the policy owner signs a root only for a tree whose routes it currently
 * allows, and {@code notAfter} is when it stops vouching for them. Renewing is signing the same tree again with a
 * new {@code notAfter}; narrowing is not renewing.
 */
public record SignedRoot(String rootId, String root, String sig, long notAfter) {

    /** The largest {@code notAfter}: 2^53 &minus; 1, beyond which the SDKs would not all print the same digits. */
    public static final long MAX_NOT_AFTER = JsonIntegers.MAX_SAFE;

    private static final String DOMAIN = "paztport-root\n";

    /**
     * Signs {@code root} under {@code rootId}, vouched for until {@code notAfter}. The caller must already have
     * checked that the tree's routes are the ones it currently allows.
     */
    public static SignedRoot sign(byte[] root, String rootId, long notAfter, PrivateKey policyKey) {
        return signText(rootId, Base64Url.encode(root), notAfter, policyKey);
    }

    /**
     * The same {@code root} and {@code rootId}, signed again until {@code notAfter}. The root text is reused as it
     * stands, so the renewed root names exactly the tree this one did. The caller must still allow every route in
     * that tree; a narrowed policy needs a new tree, not a renewal.
     */
    public SignedRoot renewed(long notAfter, PrivateKey policyKey) {
        return signText(rootId, root, notAfter, policyKey);
    }

    /**
     * True when the signature verifies under {@code policyKey}, over this root's {@code notAfter}; never throws.
     * Says nothing about time: see {@link #isCurrent}.
     */
    public boolean verify(PublicKey policyKey) {
        if (sig == null || rootId == null || root == null || policyKey == null) {
            return false;
        }
        try {
            return Crypto.verify(policyKey, signingBytes(rootId, root, notAfter), Base64Url.decode(sig));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * True when {@code nowMs <= notAfter}. Says nothing about the signature: the caller also checks
     * {@link #verify}.
     */
    public boolean isCurrent(long nowMs) {
        return nowMs <= notAfter;
    }

    public byte[] rootBytes() {
        return Base64Url.decode(root);
    }

    /** The wire form: the object's JCS text, {@code {notAfter, root, rootId, sig}} with a null field left out. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The root as a file: {@link #toJson()}'s object in the spec's file format. */
    public String toFile() {
        return JsonWriter.file(tree());
    }

    /** The header form: the base64url of {@link #toJson()}'s bytes. */
    public String encode() {
        return JsonWriter.token(tree());
    }

    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        if (rootId != null) {
            o.put("rootId", new JsonValue.Str(rootId));
        }
        if (root != null) {
            o.put("root", new JsonValue.Str(root));
        }
        if (sig != null) {
            o.put("sig", new JsonValue.Str(sig));
        }
        o.put("notAfter", new JsonValue.Int(notAfter));
        return new JsonValue.Obj(o);
    }

    /**
     * Reads the base64url text {@link #encode} writes: a token of the root's JCS bytes, held to the members
     * {@link #parse} reads. Text that is not exactly that throws {@link IllegalArgumentException}.
     */
    public static SignedRoot decode(String text) {
        return RootJson.read(JsonReader.token(text));
    }

    /**
     * The signed bytes: a domain prefix, then the JCS of {@code notAfter}, {@code root} and
     * {@code rootId}. Throws {@link IllegalArgumentException} for a null field or a {@code notAfter} out of range,
     * which nothing signs.
     */
    public static byte[] signingBytes(String rootId, String root, long notAfter) {
        if (rootId == null || root == null) {
            throw new IllegalArgumentException("a signed root needs a root id and a root");
        }
        if (!JsonIntegers.inRange(notAfter)) {
            throw new IllegalArgumentException("notAfter must be an integer in [0, 2^53 - 1]");
        }
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("notAfter", new JsonValue.Int(notAfter));
        o.put("root", new JsonValue.Str(root));
        o.put("rootId", new JsonValue.Str(rootId));
        byte[] body = JsonWriter.wire(new JsonValue.Obj(o));
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    /**
     * Reads a root as a file reads, in any member order and spacing. Throws {@link IllegalArgumentException} unless
     * {@code json} is an object of exactly string {@code rootId}, {@code root} and {@code sig} and an integer
     * {@code notAfter}: a protocol integer by its text, so {@code 1.0e12} and {@code 1798761600000.0} are refused, as
     * is any other member. The refusal names the member, or is a {@link MalformedJsonException} for text that does
     * not read.
     */
    public static SignedRoot parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("a signed root must be a JSON object");
        }
        return RootJson.read(JsonReader.fileText(json));
    }

    /**
     * Reads {@code root.json} by {@link #parse}'s rules; malformed content throws {@link IllegalArgumentException},
     * and a file that cannot be read {@link UncheckedIOException}.
     */
    public static SignedRoot load(Path file) {
        return RootJson.read(JsonReader.file(file));
    }

    private static SignedRoot signText(String rootId, String rootB64, long notAfter, PrivateKey policyKey) {
        String sig = Base64Url.encode(Crypto.sign(policyKey, signingBytes(rootId, rootB64, notAfter)));
        return new SignedRoot(rootId, rootB64, sig, notAfter);
    }
}
