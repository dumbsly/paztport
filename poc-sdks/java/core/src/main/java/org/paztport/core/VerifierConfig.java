// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PublicKey;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Everything a verifying service pins at startup. Build it with
 * {@link #pinned} so the signed root is checked against the policy key once,
 * up front; a bad policy signature fails fast rather than per request.
 */
public record VerifierConfig(
        Keyring keyring,
        byte[] root,
        String rootId,
        Set<String> allowedOrigins,
        long maxAgeMs,
        NonceCache nonceCache,
        LongSupplier clock) {

    public VerifierConfig {
        allowedOrigins = Set.copyOf(allowedOrigins);
    }

    public static VerifierConfig pinned(
            Keyring keyring,
            SignedRoot signedRoot,
            PublicKey policyKey,
            Set<String> allowedOrigins,
            long maxAgeMs,
            NonceCache nonceCache,
            LongSupplier clock) {
        if (!signedRoot.verify(policyKey)) {
            throw new IllegalArgumentException("pinned root signature does not verify against policy key");
        }
        return new VerifierConfig(
                keyring, signedRoot.rootBytes(), signedRoot.rootId(),
                allowedOrigins, maxAgeMs, nonceCache, clock);
    }
}
