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
 *
 * <p>v1 is frozen and keeps the old root form ({@link SignedRoot#signOldForm}):
 * {@link #pinned} checks the signature in whichever form the root is in, and
 * judges no validity window.
 */
public record VerifierConfigV1(
        Keyring keyring,
        byte[] root,
        String rootId,
        Set<String> allowedOrigins,
        long maxAgeMs,
        NonceCache nonceCache,
        LongSupplier clock) {

    public VerifierConfigV1 {
        allowedOrigins = Set.copyOf(allowedOrigins);
    }

    public static VerifierConfigV1 pinned(
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
        return new VerifierConfigV1(
                keyring, signedRoot.rootBytes(), signedRoot.rootId(),
                allowedOrigins, maxAgeMs, nonceCache, clock);
    }
}
