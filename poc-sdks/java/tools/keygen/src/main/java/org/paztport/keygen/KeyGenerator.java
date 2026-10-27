// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;

/**
 * Generates one Ed25519 keypair per service plus a policy keypair, and projects
 * the public half into a {@link KeyringFile}. Pure logic; file writing lives in
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

    public static KeyringFile toKeyring(Result result) {
        Map<String, String> services = new LinkedHashMap<>();
        result.services().forEach((svc, kp) ->
                services.put(svc, Base64Url.encode(Crypto.encodePublicKey(kp.getPublic()))));
        return new KeyringFile(services, Base64Url.encode(Crypto.encodePublicKey(result.policy().getPublic())), null);
    }
}
