// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * {@code reply-cert.json}: the policy key's statement that {@code key} is service {@code svc}'s reply key until
 * {@code notAfter} (milliseconds since the epoch, inclusive). The policy key stays offline, so a signed keyring
 * says nothing about whether it is still current, and a retired key listed in any keyring the policy key ever
 * signed could otherwise sign accepted replies forever. A certificate expires instead: retiring a key means not
 * reissuing its certificate, and the lifetime is the revocation delay.
 *
 * <p>The signature covers {@code utf8("paztport-reply-cert\n") || JCS({key, notAfter, policy, svc})}, and a
 * certificate has no other member but {@code sig}. {@code notAfter} is an integer in [0, 2^53 &minus; 1], the range
 * both SDKs print the same way.
 *
 * <p>What the signer must have verified: the policy owner issues a certificate only after checking that
 * {@code key} is {@code svc}'s key in its current keyring, signed by the same policy key.
 */
public record ReplyCert(String policy, String svc, String key, long notAfter, String sig) {

    /** The largest {@code notAfter}: 2^53 &minus; 1, beyond which the two SDKs would print different digits. */
    public static final long MAX_NOT_AFTER = JsonIntegers.MAX_SAFE;

    private static final String DOMAIN = "paztport-reply-cert\n";
    private static final Set<String> MEMBERS = Set.of("key", "notAfter", "policy", "sig", "svc");

    /**
     * Signs a certificate for {@code svc}'s {@code key} under the policy key. The caller must already have checked
     * that {@code key} is {@code svc}'s key in its current keyring, signed by {@code policyKey}.
     */
    public static ReplyCert issue(String policyPublicKey, String svc, String key, long notAfter, PrivateKey policyKey) {
        byte[] sig = Crypto.sign(policyKey, signingBytes(policyPublicKey, svc, key, notAfter));
        return new ReplyCert(policyPublicKey, svc, key, notAfter, Base64Url.encode(sig));
    }

    /**
     * The bytes the signature covers: a domain prefix, then the JCS of the four signed fields. Throws
     * {@link IllegalArgumentException} for a null field or a {@code notAfter} out of range, which nothing signs.
     */
    public static byte[] signingBytes(String policy, String svc, String key, long notAfter) {
        if (policy == null || svc == null || key == null) {
            throw new IllegalArgumentException("a reply certificate needs a policy key, a service and a key");
        }
        if (!JsonIntegers.inRange(notAfter)) {
            throw new IllegalArgumentException("notAfter must be an integer in [0, 2^53 - 1]");
        }
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("key", new JsonValue.Str(key));
        o.put("notAfter", new JsonValue.Int(notAfter));
        o.put("policy", new JsonValue.Str(policy));
        o.put("svc", new JsonValue.Str(svc));
        byte[] body = JsonWriter.wire(new JsonValue.Obj(o));
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    /**
     * True only when this certificate names the pinned policy key and its signature verifies under it; never
     * throws. Says nothing about time: the caller compares {@code notAfter} with the time it judges. As for the
     * keyring, the signature text must be the canonical base64url encoding, as every decoded value must.
     */
    public boolean verifies(String pinnedPolicyKey) {
        if (sig == null || policy == null || pinnedPolicyKey == null || !policy.equals(pinnedPolicyKey)) {
            return false;
        }
        try {
            return Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey)),
                    signingBytes(policy, svc, key, notAfter), Base64Url.decode(sig));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The wire form: the object's JCS text, {@code {key, notAfter, policy, sig, svc}}. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The certificate as a file: {@link #toJson()}'s object in the spec's file format. */
    public String toFile() {
        return JsonWriter.file(tree());
    }

    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("policy", new JsonValue.Str(policy));
        o.put("svc", new JsonValue.Str(svc));
        o.put("key", new JsonValue.Str(key));
        o.put("notAfter", new JsonValue.Int(notAfter));
        o.put("sig", new JsonValue.Str(sig));
        return new JsonValue.Obj(o);
    }

    /**
     * Reads a certificate as a file reads, in any member order and spacing. Throws {@link IllegalArgumentException}
     * unless {@code json} is an object of exactly string {@code policy}, {@code svc}, {@code key} and {@code sig}
     * and an integer {@code notAfter}: a protocol integer by its text, so {@code 1.0} and {@code 1e3} are refused,
     * as is any other member. The refusal names the member, or is a {@link MalformedJsonException} for text that
     * does not read.
     */
    public static ReplyCert parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("a reply certificate must be a JSON object");
        }
        return fromTree(JsonReader.fileText(json));
    }

    /**
     * Reads {@code reply-cert.json} by {@link #parse}'s rules; malformed content throws
     * {@link IllegalArgumentException}, and a file that cannot be read {@link UncheckedIOException}.
     */
    public static ReplyCert load(Path file) {
        return fromTree(JsonReader.file(file));
    }

    /** The certificate's schema, which a session reply's own reader applies to the certificate it holds. */
    static ReplyCert fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        return new ReplyCert(JsonFields.string(o, "policy"), JsonFields.string(o, "svc"), JsonFields.string(o, "key"),
                JsonFields.integer(o, "notAfter"), JsonFields.string(o, "sig"));
    }
}
