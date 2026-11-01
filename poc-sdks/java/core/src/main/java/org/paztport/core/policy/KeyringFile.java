// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

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
 * The on-disk {@code keyring.json}: every service's public key plus the policy public key, each as a base64url
 * X.509 string, and the policy key's signature over both. Public material only. A verifier pins the policy key
 * out of band and trusts the service keys only if {@link #verifies} says the file was signed under that pin, so
 * the keyring does not vouch for its own policy key. {@code sig} is null only for a keyring built unsigned in
 * code: a file always carries one.
 *
 * <p>The policy key stays offline, so a keyring it once signed would otherwise vouch for its service keys for
 * ever, a retired or stolen key among them. A keyring therefore carries {@code notAfter} (milliseconds since the
 * epoch, inclusive) and its signature covers {@code utf8("paztport-keyring\n") || JCS({notAfter, policy,
 * services})}.
 *
 * <p>What the signer must have verified: the policy owner signs a keyring only after checking that each listed key
 * is that service's current key, and {@code notAfter} is when it stops vouching for them.
 */
public record KeyringFile(Map<String, String> services, String policy, String sig, long notAfter) {

    /** The largest {@code notAfter}: 2^53 &minus; 1, beyond which the two SDKs would print different digits. */
    public static final long MAX_NOT_AFTER = JsonIntegers.MAX_SAFE;

    private static final String DOMAIN = "paztport-keyring\n";
    private static final Set<String> MEMBERS = Set.of("notAfter", "policy", "services", "sig");

    public KeyringFile {
        services = Map.copyOf(services);
    }

    /**
     * The signed bytes: a domain prefix, then the JCS of {@code notAfter}, the policy key and the services. Throws
     * {@link IllegalArgumentException} for a {@code notAfter} out of range, which nothing signs.
     */
    public static byte[] signingBytes(String policy, Map<String, String> services, long notAfter) {
        if (!JsonIntegers.inRange(notAfter)) {
            throw new IllegalArgumentException("notAfter must be an integer in [0, 2^53 - 1]");
        }
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("notAfter", new JsonValue.Int(notAfter));
        o.put("policy", new JsonValue.Str(policy));
        o.put("services", servicesJson(services));
        byte[] body = JsonWriter.wire(new JsonValue.Obj(o));
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    /**
     * Signs the keyring, vouching for {@code services} until {@code notAfter}. The caller must already have
     * checked that each key is that service's current key.
     */
    public static KeyringFile sign(Map<String, String> services, String policyPublicKey, long notAfter,
            PrivateKey policyKey) {
        byte[] sig = Crypto.sign(policyKey, signingBytes(policyPublicKey, services, notAfter));
        return new KeyringFile(services, policyPublicKey, Base64Url.encode(sig), notAfter);
    }

    /**
     * The same services and policy key, signed again until {@code notAfter}. The caller must still hold every listed
     * key to be its service's current key; a retired key needs a new keyring, not a renewal.
     */
    public KeyringFile renewed(long notAfter, PrivateKey policyKey) {
        return sign(services, policy, notAfter, policyKey);
    }

    /**
     * True only when this file names the pinned policy key and its signature verifies under it, over its
     * {@code notAfter}; never throws. Says nothing about time: see {@link #isCurrent}. The signature text must be
     * the canonical base64url encoding, as every decoded value must.
     */
    public boolean verifies(String pinnedPolicyKey) {
        if (sig == null || policy == null || pinnedPolicyKey == null || !policy.equals(pinnedPolicyKey)) {
            return false;
        }
        try {
            return Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey)),
                    signingBytes(policy, services, notAfter), Base64Url.decode(sig));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * True when {@code nowMs <= notAfter}. Says nothing about the signature: the caller also checks
     * {@link #verifies}.
     */
    public boolean isCurrent(long nowMs) {
        return nowMs <= notAfter;
    }

    /**
     * Reads a keyring as a file reads, in any member order and spacing. Throws {@link IllegalArgumentException}
     * unless {@code json} is an object of exactly a string {@code policy}, a string {@code sig}, a {@code services}
     * object naming each service by a route node, its every value a string, and an integer {@code notAfter}: a
     * protocol integer by its text, so {@code 1.0e12} and {@code 1798761600000.0} are refused, as is any other
     * member. The refusal names the member, or is a {@link MalformedJsonException} for text that does not read.
     */
    public static KeyringFile parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("a keyring must be a JSON object");
        }
        return fromTree(JsonReader.fileText(json));
    }

    /**
     * Reads {@code keyring.json} by {@link #parse}'s rules; malformed content throws
     * {@link IllegalArgumentException}, and a file that cannot be read {@link UncheckedIOException}.
     */
    public static KeyringFile load(Path file) {
        return fromTree(JsonReader.file(file));
    }

    /** The keyring's schema. A service's name is data, checked by the route-node rule rather than named. */
    private static KeyringFile fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        Map<String, String> services = JsonFields.stringMap(JsonFields.object(o, "services"));
        for (String name : services.keySet()) {
            try {
                Routes.requireValidNode(name);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("member services holds a name that is not a route node");
            }
        }
        return new KeyringFile(services, JsonFields.string(o, "policy"), JsonFields.string(o, "sig"),
                JsonFields.integer(o, "notAfter"));
    }

    /**
     * The wire form: the object's JCS text, {@code {notAfter, policy, services, sig?}} with a null {@code sig} left
     * out.
     */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The keyring as a file: {@link #toJson()}'s object in the spec's file format. */
    public String toFile() {
        return JsonWriter.file(tree());
    }

    private JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("services", servicesJson(services));
        o.put("policy", new JsonValue.Str(policy));
        if (sig != null) {
            o.put("sig", new JsonValue.Str(sig));
        }
        o.put("notAfter", new JsonValue.Int(notAfter));
        return new JsonValue.Obj(o);
    }

    private static JsonValue.Obj servicesJson(Map<String, String> services) {
        Map<String, JsonValue> s = new LinkedHashMap<>();
        services.forEach((name, key) -> s.put(name, new JsonValue.Str(key)));
        return new JsonValue.Obj(s);
    }
}
