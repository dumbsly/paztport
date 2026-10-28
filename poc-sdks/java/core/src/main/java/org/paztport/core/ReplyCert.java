// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

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

/**
 * {@code reply-cert.json}: the policy key's statement that {@code key} is service {@code svc}'s reply key until
 * {@code notAfter} (milliseconds since the epoch, inclusive). The policy key stays offline, so a signed keyring
 * says nothing about whether it is still current, and a retired key listed in any keyring the policy key ever
 * signed could otherwise sign accepted replies forever. A certificate expires instead: retiring a key means not
 * reissuing its certificate, and the lifetime is the revocation delay.
 *
 * <p>The signature covers {@code utf8("paztport-reply-cert\n") || JCS({key, notAfter, policy, svc})}; any other
 * field on the wire is ignored and unsigned. {@code notAfter} is an integer in [0, 2^53 &minus; 1], the range both
 * SDKs print the same way.
 *
 * <p>What the signer must have verified: the policy owner issues a certificate only after checking that
 * {@code key} is {@code svc}'s key in its current keyring, signed by the same policy key.
 */
public record ReplyCert(String policy, String svc, String key, long notAfter, String sig) {

    /** The largest {@code notAfter}: 2^53 &minus; 1, beyond which the two SDKs would print different digits. */
    public static final long MAX_NOT_AFTER = (1L << 53) - 1;

    private static final String DOMAIN = "paztport-reply-cert\n";
    private static final ObjectMapper READER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

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
        if (!inRange(notAfter)) {
            throw new IllegalArgumentException("notAfter must be an integer in [0, 2^53 - 1]");
        }
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("key", key);
        o.put("notAfter", notAfter);
        o.put("policy", policy);
        o.put("svc", svc);
        byte[] body = Jcs.bytes(o);
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    /**
     * True only when this certificate names the pinned policy key and its signature verifies under it; never
     * throws. Says nothing about time: the caller compares {@code notAfter} with the time it judges. As for the
     * keyring, the signature text is not held to the canonical-encoding rule.
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

    /** The wire form, fields in the order the spec lists them. */
    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("policy", policy);
        o.put("svc", svc);
        o.put("key", key);
        o.put("notAfter", notAfter);
        o.put("sig", sig);
        return o;
    }

    /**
     * Reads the wire form. Throws {@link IllegalArgumentException} unless {@code node} is an object with string
     * {@code policy}, {@code svc}, {@code key} and {@code sig} and an in-range integer {@code notAfter}. Only an
     * integer JSON number counts: a string, a fraction, and an integral float such as {@code 1.0} or {@code 1e3}
     * are refused, so what is accepted is exactly what JCS prints. Other fields are ignored.
     */
    public static ReplyCert parse(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("a reply certificate must be a JSON object");
        }
        JsonNode n = node.get("notAfter");
        if (n == null || !n.isIntegralNumber() || !n.canConvertToLong() || !inRange(n.longValue())) {
            throw new IllegalArgumentException("reply certificate notAfter must be an integer in [0, 2^53 - 1]");
        }
        return new ReplyCert(text(node, "policy"), text(node, "svc"), text(node, "key"), n.longValue(),
                text(node, "sig"));
    }

    /** Reads {@code reply-cert.json}; malformed content throws {@link IllegalArgumentException}. */
    public static ReplyCert load(Path file) {
        JsonNode node;
        try {
            node = READER.readTree(Files.readAllBytes(file));
        } catch (JacksonException e) {
            throw new IllegalArgumentException("malformed reply certificate " + file, e);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
        return parse(node);
    }

    private static boolean inRange(long v) {
        return v >= 0 && v <= MAX_NOT_AFTER;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || !v.isTextual()) {
            throw new IllegalArgumentException("reply certificate " + field + " must be a string");
        }
        return v.textValue();
    }
}
