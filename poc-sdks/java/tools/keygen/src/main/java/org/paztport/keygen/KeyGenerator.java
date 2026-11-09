// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;

/**
 * Generates one Ed25519 keypair per service plus a policy keypair, and projects
 * the public half into a {@link KeyringFile} signed by the policy key. Pure logic; file writing lives in
 * {@link KeygenMain}.
 */
public final class KeyGenerator {

    private KeyGenerator() {
    }

    /** All generated keypairs: one per service, keyed by name, plus the policy keypair. */
    public record Result(Map<String, KeyPair> services, KeyPair policy) {
        public Result {
            services = new LinkedHashMap<>(services);
        }
    }

    public static Result generate(List<String> serviceNames) {
        Map<String, KeyPair> services = new LinkedHashMap<>();
        for (String svc : serviceNames) {
            services.put(svc, Crypto.generateEd25519KeyPair());
        }
        return new Result(services, Crypto.generateEd25519KeyPair());
    }

    /** The policy public key, base64url: the value a verifier pins out of band. */
    public static String policyPublicKey(Result result) {
        return Base64Url.encode(Crypto.encodePublicKey(result.policy().getPublic()));
    }

    /**
     * The keyring, signed by the policy key so that a verifier holding the pin need not trust the file's origin, and
     * stops trusting it after {@code notAfter} (milliseconds since the epoch, inclusive). What the signature vouches
     * for holds by construction: every listed key is the one just generated for its service.
     */
    public static KeyringFile toKeyring(Result result, long notAfter) {
        Map<String, String> services = new LinkedHashMap<>();
        result.services().forEach((svc, kp) ->
                services.put(svc, Base64Url.encode(Crypto.encodePublicKey(kp.getPublic()))));
        return KeyringFile.sign(services, policyPublicKey(result), notAfter, result.policy().getPrivate());
    }
}
