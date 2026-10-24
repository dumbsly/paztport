// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/** The public keys of every known service, keyed by service name. */
public final class Keyring {

    private final Map<String, PublicKey> keys;

    private Keyring(Map<String, PublicKey> keys) {
        this.keys = Map.copyOf(keys);
    }

    public static Keyring of(Map<String, PublicKey> keys) {
        return new Keyring(keys);
    }

    /** Decodes a {@link KeyringFile}'s base64url X.509 service keys into a usable keyring. */
    public static Keyring fromFile(KeyringFile file) {
        Map<String, PublicKey> decoded = new LinkedHashMap<>();
        file.services().forEach((svc, b64) -> decoded.put(svc, Crypto.decodePublicKey(Base64Url.decode(b64))));
        return new Keyring(decoded);
    }

    /** The public key for a service, or null if the service is unknown (fail closed). */
    public PublicKey keyFor(String svc) {
        return keys.get(svc);
    }
}
