// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * Everything a verifier pins at startup. Build it with {@link #pinned} so each keyring and signed root is checked
 * against the pinned policy key once, up front; a bad signature fails fast rather than per request. Freshness is
 * explicit: {@code callMaxAgeMs} bounds the last stamp's age, {@code runMaxAgeMs} the origin's.
 *
 * <p>It pins one or more keyrings and one or more roots, each with its own {@code notAfter}, so a rollover can pin
 * the old and the new together; the verifier uses only those current at its clock. Both lists are copied, and an
 * empty one, or a null member, is refused here, so no check meets one.
 *
 * <p>{@code policyNotAfter} is the earlier of the latest keyring {@code notAfter} and the latest root {@code notAfter}
 * (milliseconds since the epoch, inclusive; {@link #policyNotAfter(List, List)}): the last moment the policy owner
 * vouches for some keyring and some root. The verifier refuses every request once its clock passes it, so a verifier
 * left running is not trusted for longer than its material. {@link #pinned} records it; a direct constructor is for
 * tests and vectors that hold material already judged. The constructor does not range-check it: the verifier's
 * check 0 refuses every request under a window outside [0, 2^53 &minus; 1], as the spec and the TypeScript verifier
 * do, so a vector pins one answer for both.
 */
public record VerifierConfig(
        List<PinnedKeyring> keyrings,
        List<PinnedRoot> roots,
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
     * twice the window if that is longer, and {@code Long.MAX_VALUE} when twice the window does not fit a
     * long. The verifier refuses a cache that forgets sooner, so a service that widens its window sizes its cache
     * with this.
     */
    public static long nonceTtlFor(long callMaxAgeMs) {
        if (callMaxAgeMs > Long.MAX_VALUE / 2) {
            return Long.MAX_VALUE;
        }
        return Math.max(NONCE_TTL_MS, 2 * callMaxAgeMs);
    }

    public VerifierConfig {
        keyrings = ChainChecks.members(keyrings, "keyrings");
        roots = ChainChecks.members(roots, "roots");
        Objects.requireNonNull(sess, "sess");
        Objects.requireNonNull(nonces, "nonces");
        Objects.requireNonNull(clock, "clock");
        allowedOrigins = Set.copyOf(allowedOrigins);
    }

    /**
     * The window {@link #pinned} records for these members: the earlier of the latest keyring {@code notAfter} and
     * the latest root {@code notAfter}, past which no keyring, or no root, is current. Throws
     * {@link IllegalArgumentException} for an empty list, as the constructor does.
     */
    public static long policyNotAfter(List<PinnedKeyring> keyrings, List<PinnedRoot> roots) {
        long keyring = ChainChecks.members(keyrings, "keyrings").stream().mapToLong(PinnedKeyring::notAfter).max()
                .orElseThrow();
        long root = ChainChecks.members(roots, "roots").stream().mapToLong(PinnedRoot::notAfter).max().orElseThrow();
        return Math.min(keyring, root);
    }

    /**
     * Pins the policy key, a base64url SPKI string (the {@code policy.pub} text): every keyring file must name it and
     * verify under it, and so must every signed root. Each must also be current at {@code at}, the time it is judged
     * (milliseconds since the epoch): the policy owner no longer vouches for an expired one. The verifier keeps
     * {@code clock}, which it reads live for every request, so {@code at} is a reading taken once, as at startup, and
     * never the clock itself. Throws {@link IllegalArgumentException} otherwise, naming the member by its
     * place in its list ({@code keyrings[1]}), so a verifier is never built on material the pin does not vouch for
     * now; and for an empty list. Each member keeps its own window, and {@link #policyNotAfter(List, List)} of them is
     * recorded as {@code policyNotAfter}.
     */
    public static VerifierConfig pinned(
            List<KeyringFile> keyrings,
            List<SignedRoot> roots,
            String pinnedPolicyKey,
            long at,
            Set<String> allowedOrigins,
            String sess,
            NonceCache nonces,
            LongSupplier clock,
            long callMaxAgeMs,
            long runMaxAgeMs) {
        ChainChecks.members(keyrings, "keyrings");
        ChainChecks.members(roots, "roots");
        List<PinnedKeyring> pinnedKeyrings = new ArrayList<>();
        for (int i = 0; i < keyrings.size(); i++) {
            pinnedKeyrings.add(keyring(keyrings.get(i), "keyrings[" + i + "]", pinnedPolicyKey, at));
        }
        PublicKey pin;
        try {
            pin = Crypto.decodePublicKey(Base64Url.decode(pinnedPolicyKey));
        } catch (RuntimeException e) {
            pin = null;
        }
        List<PinnedRoot> pinnedRoots = new ArrayList<>();
        for (int i = 0; i < roots.size(); i++) {
            pinnedRoots.add(root(roots.get(i), "roots[" + i + "]", pin, at));
        }
        return new VerifierConfig(pinnedKeyrings, pinnedRoots, policyNotAfter(pinnedKeyrings, pinnedRoots),
                allowedOrigins, sess, nonces, clock, callMaxAgeMs, runMaxAgeMs);
    }

    /** {@code keyring}, named {@code name}, once it verifies under the pin and is current at {@code now}. */
    private static PinnedKeyring keyring(KeyringFile keyring, String name, String pinnedPolicyKey, long now) {
        if (!keyring.verifies(pinnedPolicyKey)) {
            throw new IllegalArgumentException(name + " does not verify under the pinned policy key");
        }
        if (!keyring.isCurrent(now)) {
            throw new IllegalArgumentException(name + " expired: " + window(keyring.notAfter(), now));
        }
        return new PinnedKeyring(Keyring.fromFile(keyring), keyring.notAfter());
    }

    /** {@code root}, named {@code name}, once it verifies under {@code pin}, null for none, and is current. */
    private static PinnedRoot root(SignedRoot root, String name, PublicKey pin, long now) {
        boolean rootOk;
        try {
            rootOk = pin != null && root.verify(pin);
        } catch (RuntimeException e) {
            rootOk = false;
        }
        if (!rootOk) {
            throw new IllegalArgumentException(name + " does not verify under the pinned policy key");
        }
        if (!root.isCurrent(now)) {
            throw new IllegalArgumentException(name + " expired: " + window(root.notAfter(), now));
        }
        byte[] bytes;
        try {
            bytes = root.rootBytes();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(name + " is not base64url", e);
        }
        return new PinnedRoot(bytes, root.rootId(), root.notAfter());
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
