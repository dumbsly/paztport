// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PublicKey;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Everything a v3 verifier pins at startup. Build it with {@link #pinned} so the keyring and the signed root
 * are checked against the pinned policy key once, up front; a bad signature fails fast rather than per request.
 * Freshness is explicit: {@code callMaxAgeMs} bounds the last stamp's age, {@code runMaxAgeMs} the origin's.
 */
public record VerifierConfigV3(
        Keyring keyring,
        byte[] root,
        String rootId,
        Set<String> allowedOrigins,
        String sess,
        NonceCache nonces,
        LongSupplier clock,
        long callMaxAgeMs,
        long runMaxAgeMs) {

    /** How recent the last stamp must be, either side of now. */
    public static final long CALL_MAX_AGE_MS = 5000;
    /** How old a run's origin stamp may be. */
    public static final long RUN_MAX_AGE_MS = 1_800_000;
    /** Nonce caches must remember keys for at least twice the call freshness window. */
    public static final long NONCE_TTL_MS = 15_000;

    public VerifierConfigV3 {
        Objects.requireNonNull(keyring, "keyring");
        Objects.requireNonNull(root, "root");
        Objects.requireNonNull(rootId, "rootId");
        Objects.requireNonNull(sess, "sess");
        Objects.requireNonNull(nonces, "nonces");
        Objects.requireNonNull(clock, "clock");
        allowedOrigins = Set.copyOf(allowedOrigins);
        root = root.clone();
    }

    /**
     * Pins the policy key, a base64url SPKI string (the {@code policy.pub} text): the keyring file must name it
     * and verify under it, and so must the signed root. Throws {@link IllegalArgumentException} otherwise, so a
     * verifier is never built on material the pin does not vouch for.
     */
    public static VerifierConfigV3 pinned(
            KeyringFile keyring,
            SignedRoot root,
            String pinnedPolicyKey,
            Set<String> allowedOrigins,
            String sess,
            NonceCache nonces,
            LongSupplier clock,
            long callMaxAgeMs,
            long runMaxAgeMs) {
        if (!keyring.verifies(pinnedPolicyKey)) {
            throw new IllegalArgumentException("keyring does not verify under the pinned policy key");
        }
        boolean rootOk;
        try {
            PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey));
            rootOk = root.verify(pin);
        } catch (RuntimeException e) {
            rootOk = false;
        }
        if (!rootOk) {
            throw new IllegalArgumentException("root does not verify under the pinned policy key");
        }
        byte[] rootBytes;
        try {
            rootBytes = root.rootBytes();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("root is not base64url", e);
        }
        return new VerifierConfigV3(Keyring.fromFile(keyring), rootBytes, root.rootId(), allowedOrigins, sess,
                nonces, clock, callMaxAgeMs, runMaxAgeMs);
    }
}
