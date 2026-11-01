// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * Everything a verifier pins at startup. Build it with {@link #pinned} so the keyring and the signed root
 * are checked against the pinned policy key once, up front; a bad signature fails fast rather than per request.
 * Freshness is explicit: {@code callMaxAgeMs} bounds the last stamp's age, {@code runMaxAgeMs} the origin's.
 *
 * <p>{@code policyNotAfter} is the earliest {@code notAfter} of the keyring and the root (milliseconds since the
 * epoch, inclusive): the last moment the policy owner vouches for both. The verifier refuses every request once
 * its clock passes it, so a verifier left running is not trusted for longer than its material. {@link #pinned}
 * records it; a direct constructor is for tests and vectors that hold material already judged. The constructor does
 * not range-check it: the verifier's check 0 refuses every request under a window outside [0, 2^53 &minus; 1], as the
 * spec and the TypeScript verifier do, so a vector pins one answer for both.
 */
public record VerifierConfig(
        Keyring keyring,
        byte[] root,
        String rootId,
        long policyNotAfter,
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

    /**
     * How long a nonce cache must remember for a call window of {@code callMaxAgeMs}: {@link #NONCE_TTL_MS}, or
     * twice the window if that is longer. The verifier refuses a cache that forgets sooner, so a service that
     * widens its window sizes its cache with this.
     */
    public static long nonceTtlFor(long callMaxAgeMs) {
        return Math.max(NONCE_TTL_MS, 2 * callMaxAgeMs);
    }

    public VerifierConfig {
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
     * and verify under it, and so must the signed root. Both must also be current by {@code clock}: the policy owner
     * no longer vouches for an expired one. Throws {@link IllegalArgumentException} otherwise, naming the keyring
     * or the root, so a verifier is never built on material the pin does not vouch for now. The earlier of the two
     * windows is recorded as {@code policyNotAfter}.
     */
    public static VerifierConfig pinned(
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
        long now = clock.getAsLong();
        if (!keyring.isCurrent(now)) {
            throw new IllegalArgumentException("keyring expired: " + window(keyring.notAfter(), now));
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
        if (!root.isCurrent(now)) {
            throw new IllegalArgumentException("root expired: " + window(root.notAfter(), now));
        }
        byte[] rootBytes;
        try {
            rootBytes = root.rootBytes();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("root is not base64url", e);
        }
        return new VerifierConfig(Keyring.fromFile(keyring), rootBytes, root.rootId(),
                Math.min(keyring.notAfter(), root.notAfter()), allowedOrigins, sess, nonces, clock, callMaxAgeMs,
                runMaxAgeMs);
    }

    /**
     * The window and the clock, each as its integer then its instant. Never throws, since an {@link Instant} spans
     * every {@code long} of milliseconds; the integer leads because it is what was signed.
     */
    private static String window(long notAfter, long now) {
        return "notAfter " + notAfter + " (" + Instant.ofEpochMilli(notAfter) + ") is before now " + now + " ("
                + Instant.ofEpochMilli(now) + ")";
    }
}
