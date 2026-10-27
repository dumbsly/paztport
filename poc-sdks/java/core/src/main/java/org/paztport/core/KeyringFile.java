// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Map;

/**
 * The on-disk {@code keyring.json}: every service's public key plus the policy public key, each as a base64url
 * X.509 string, and the policy key's signature over both. Public material only. A verifier pins the policy key
 * out of band and trusts the service keys only if {@link #verifies} says the file was signed under that pin, so
 * the keyring no longer vouches for its own policy key. {@code sig} is null for an unsigned file.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record KeyringFile(Map<String, String> services, String policy, String sig) {

    private static final String DOMAIN = "paztport-keyring\n";

    public KeyringFile {
        services = Map.copyOf(services);
    }

    /** The bytes the signature covers: a domain prefix, then the JCS of the policy key and the services. */
    public static byte[] signingBytes(String policy, Map<String, String> services) {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("policy", policy);
        ObjectNode s = o.putObject("services");
        services.forEach(s::put);
        byte[] body = Jcs.bytes(o);
        byte[] prefix = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    public static KeyringFile sign(Map<String, String> services, String policyPublicKey, PrivateKey policyKey) {
        byte[] sig = Crypto.sign(policyKey, signingBytes(policyPublicKey, services));
        return new KeyringFile(services, policyPublicKey, Base64Url.encode(sig));
    }

    /** True only when this file names the pinned policy key and its signature verifies under it; never throws. */
    public boolean verifies(String pinnedPolicyKey) {
        if (sig == null || policy == null || pinnedPolicyKey == null || !policy.equals(pinnedPolicyKey)) {
            return false;
        }
        try {
            byte[] raw = Base64Url.decode(sig);
            return Base64Url.encode(raw).equals(sig)
                    && Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey)),
                            signingBytes(policy, services), raw);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
