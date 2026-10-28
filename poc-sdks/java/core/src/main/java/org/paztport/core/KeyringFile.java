// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The on-disk {@code keyring.json}: every service's public key plus the policy public key, each as a base64url
 * X.509 string, and the policy key's signature over both. Public material only. A verifier pins the policy key
 * out of band and trusts the service keys only if {@link #verifies} says the file was signed under that pin, so
 * the keyring no longer vouches for its own policy key. {@code sig} is null for an unsigned file.
 *
 * <p>The policy key stays offline, so a keyring it once signed would otherwise vouch for its service keys for
 * ever, a retired or stolen key among them. The new form therefore carries {@code notAfter} (milliseconds since
 * the epoch, inclusive) and its signature covers {@code utf8("paztport-keyring\n") || JCS({notAfter, policy,
 * services})}. The old form, the same prefix over {@code JCS({policy, services})}, still verifies because recorded
 * evidence carries it; it is never {@linkplain #isCurrent current}. Which form a keyring is in is decided by
 * whether {@code notAfter} is present and by nothing else; dropping or adding it breaks the signature, as the
 * signed object then has a different set of members.
 *
 * <p>What the signer must have verified: the policy owner signs a keyring only after checking that each listed key
 * is that service's current key, and {@code notAfter} is when it stops vouching for them.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record KeyringFile(Map<String, String> services, String policy, String sig, Long notAfter) {

    /** The largest {@code notAfter}: 2^53 &minus; 1, beyond which the two SDKs would print different digits. */
    public static final long MAX_NOT_AFTER = JsonIntegers.MAX_SAFE;

    private static final String DOMAIN = "paztport-keyring\n";
    private static final ObjectMapper READER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public KeyringFile {
        services = Map.copyOf(services);
    }

    /** An old-form keyring, with no validity window. */
    public KeyringFile(Map<String, String> services, String policy, String sig) {
        this(services, policy, sig, null);
    }

    /** The old form's signed bytes: a domain prefix, then the JCS of the policy key and the services. */
    public static byte[] signingBytes(String policy, Map<String, String> services) {
        return withPrefix(body(policy, services));
    }

    /**
     * The new form's signed bytes: the same domain prefix, then the JCS of {@code notAfter}, the policy key and the
     * services. Throws {@link IllegalArgumentException} for a {@code notAfter} out of range, which nothing signs.
     */
    public static byte[] signingBytes(String policy, Map<String, String> services, long notAfter) {
        if (!inRange(notAfter)) {
            throw new IllegalArgumentException("notAfter must be an integer in [0, 2^53 - 1]");
        }
        ObjectNode o = body(policy, services);
        o.put("notAfter", notAfter);
        return withPrefix(o);
    }

    /**
     * Signs the old form, with no validity window. Kept for the producers that have not moved to the new form;
     * a verifier holding a live call to its rules will refuse such a keyring.
     */
    public static KeyringFile sign(Map<String, String> services, String policyPublicKey, PrivateKey policyKey) {
        byte[] sig = Crypto.sign(policyKey, signingBytes(policyPublicKey, services));
        return new KeyringFile(services, policyPublicKey, Base64Url.encode(sig));
    }

    /**
     * Signs the new form, vouching for {@code services} until {@code notAfter}. The caller must already have
     * checked that each key is that service's current key.
     */
    public static KeyringFile sign(Map<String, String> services, String policyPublicKey, long notAfter,
            PrivateKey policyKey) {
        byte[] sig = Crypto.sign(policyKey, signingBytes(policyPublicKey, services, notAfter));
        return new KeyringFile(services, policyPublicKey, Base64Url.encode(sig), notAfter);
    }

    /**
     * The same services and policy key, signed again in the new form until {@code notAfter}. The caller must still
     * hold every listed key to be its service's current key; a retired key needs a new keyring, not a renewal.
     */
    public KeyringFile renewed(long notAfter, PrivateKey policyKey) {
        return sign(services, policy, notAfter, policyKey);
    }

    /**
     * True only when this file names the pinned policy key and its signature verifies under it, in the file's own
     * form; never throws. Says nothing about time: see {@link #isCurrent}. The signature text is not held to the
     * canonical-encoding rule (that covers stamp signatures), matching the TypeScript SDK: the pin and the
     * signature are what vouch for the file.
     */
    public boolean verifies(String pinnedPolicyKey) {
        if (sig == null || policy == null || pinnedPolicyKey == null || !policy.equals(pinnedPolicyKey)) {
            return false;
        }
        try {
            byte[] signed = notAfter == null
                    ? signingBytes(policy, services)
                    : signingBytes(policy, services, notAfter);
            return Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey)), signed,
                    Base64Url.decode(sig));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** True when this keyring carries a validity window, which is what makes it the new form. Not a wire field. */
    @JsonIgnore
    public boolean isNewForm() {
        return notAfter != null;
    }

    /**
     * True when this is a new-form keyring and {@code nowMs <= notAfter}. An old-form keyring is never current.
     * Says nothing about the signature: the caller also checks {@link #verifies}.
     */
    public boolean isCurrent(long nowMs) {
        return notAfter != null && nowMs <= notAfter;
    }

    /**
     * Reads the wire form. Throws {@link IllegalArgumentException} unless {@code node} is an object with a string
     * {@code policy}, a {@code services} object whose every value is a string, a string {@code sig} if one is
     * present (an unsigned file has none), and, if {@code notAfter} is present at all, an integer in
     * [0, 2^53 &minus; 1] judged by value as a reply certificate's is: {@code 1.0e12} is an integer, while a
     * fraction, a string or {@code null} is refused rather than read as an old-form keyring, so a damaged window
     * can never pass as no window. Other fields are ignored and unsigned. Jackson's record binding would truncate
     * {@code 1.5} to 1, which is why this, not binding, is the reader.
     */
    public static KeyringFile parse(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("a keyring must be a JSON object");
        }
        JsonNode s = node.get("services");
        if (s == null || !s.isObject()) {
            throw new IllegalArgumentException("keyring services must be an object");
        }
        Map<String, String> services = new LinkedHashMap<>();
        s.fields().forEachRemaining(e -> {
            if (!e.getValue().isTextual()) {
                throw new IllegalArgumentException("keyring service keys must be strings");
            }
            services.put(e.getKey(), e.getValue().textValue());
        });
        String sig = null;
        if (node.has("sig")) {
            sig = text(node, "sig");
        }
        Long notAfter = null;
        if (node.has("notAfter")) {
            notAfter = JsonIntegers.safeInteger(node.get("notAfter"));
            if (notAfter == null || !inRange(notAfter)) {
                throw new IllegalArgumentException("keyring notAfter must be an integer in [0, 2^53 - 1]");
            }
        }
        return new KeyringFile(services, text(node, "policy"), sig, notAfter);
    }

    /** Reads {@code keyring.json}; malformed content throws {@link IllegalArgumentException}. */
    public static KeyringFile load(Path file) {
        JsonNode node;
        try {
            node = READER.readTree(Files.readAllBytes(file));
        } catch (JacksonException e) {
            throw new IllegalArgumentException("malformed keyring " + file, e);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
        return parse(node);
    }

    private static ObjectNode body(String policy, Map<String, String> services) {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("policy", policy);
        ObjectNode s = o.putObject("services");
        services.forEach(s::put);
        return o;
    }

    private static byte[] withPrefix(ObjectNode o) {
        byte[] body = Jcs.bytes(o);
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    private static boolean inRange(long v) {
        return v >= 0 && v <= MAX_NOT_AFTER;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || !v.isTextual()) {
            throw new IllegalArgumentException("keyring " + field + " must be a string");
        }
        return v.textValue();
    }
}
