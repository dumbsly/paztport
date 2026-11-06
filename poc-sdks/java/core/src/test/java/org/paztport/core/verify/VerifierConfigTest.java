// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * What {@link VerifierConfig#pinned} refuses at build time, a keyring or root that does not verify or is past its
 * window, and what a config holds: one or more of each, copied, and the window they leave it.
 */
class VerifierConfigTest {

    private static final long NOW = 1_800_000_000_000L;
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final String PIN = Base64Url.encode(Crypto.encodePublicKey(POLICY.getPublic()));
    private static final Map<String, String> SERVICES = Map.of("session",
            Base64Url.encode(Crypto.encodePublicKey(Crypto.generateEd25519KeyPair().getPublic())));
    private static final byte[] ROOT = new byte[32];

    private static KeyringFile ring(long notAfter) {
        return KeyringFile.sign(SERVICES, PIN, notAfter, POLICY.getPrivate());
    }

    private static SignedRoot root(long notAfter) {
        return SignedRoot.sign(ROOT, "v1", notAfter, POLICY.getPrivate());
    }

    private static VerifierConfig pinned(List<KeyringFile> keyrings, List<SignedRoot> roots, long now) {
        return VerifierConfig.pinned(keyrings, roots, PIN, now, Set.of("session"), "s",
                new InMemoryNonceCache(), () -> now, 5000, 5000);
    }

    private static VerifierConfig pinned(KeyringFile keyring, SignedRoot root, long now) {
        return pinned(List.of(keyring), List.of(root), now);
    }

    private static void refused(List<KeyringFile> keyrings, List<SignedRoot> roots, String... words) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> pinned(keyrings, roots, NOW));
        for (String w : words) {
            assertTrue(e.getMessage().contains(w), e.getMessage() + " should name " + w);
        }
    }

    private static void refused(KeyringFile keyring, SignedRoot root, String... words) {
        refused(List.of(keyring), List.of(root), words);
    }

    @Test
    void expiredKeyringRefusedAtBuild() {
        refused(ring(NOW - 1), root(NOW + 1000), "keyring", "expired", Long.toString(NOW - 1));
    }

    @Test
    void expiredRootRefusedAtBuild() {
        refused(ring(NOW + 1000), root(NOW - 1), "root", "expired", Long.toString(NOW - 1));
    }

    @Test
    void membersAreJudgedAtTheGivenTimeAndTheConfigKeepsTheLiveClock() {
        long[] clock = {NOW + 5000};
        VerifierConfig cfg = VerifierConfig.pinned(List.of(ring(NOW + 1000)), List.of(root(NOW + 1000)), PIN, NOW,
                Set.of("session"), "s", new InMemoryNonceCache(), () -> clock[0], 5000, 5000);
        assertEquals(NOW + 5000, cfg.clock().getAsLong(), "judging at NOW did not read the clock");
        clock[0] = NOW + 6000;
        assertEquals(NOW + 6000, cfg.clock().getAsLong(), "the config's clock is the live one");
        assertThrows(IllegalArgumentException.class, () -> VerifierConfig.pinned(List.of(ring(NOW + 1000)),
                List.of(root(NOW + 1000)), PIN, NOW + 1001, Set.of("session"), "s", new InMemoryNonceCache(),
                () -> NOW, 5000, 5000));
    }

    @Test
    void theLargestNotAfterIsNamedWithoutThrowing() {
        // 2^53 - 1 is far beyond any date a formatter is asked about here; the message must still be written.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> pinned(ring(KeyringFile.MAX_NOT_AFTER), root(NOW + 1000), KeyringFile.MAX_NOT_AFTER + 1));
        assertTrue(e.getMessage().contains(Long.toString(KeyringFile.MAX_NOT_AFTER)), e.getMessage());
    }

    @Test
    void atNotAfterBuildsAndRecordsTheEarliestWindow() {
        assertEquals(NOW, pinned(ring(NOW), root(NOW + 1000), NOW).policyNotAfter());
        assertEquals(NOW, pinned(ring(NOW + 1000), root(NOW), NOW).policyNotAfter());
    }

    @Test
    void aBadSignatureIsStillReportedAsOne() {
        KeyringFile forged = KeyringFile.sign(SERVICES, PIN, NOW - 1, Crypto.generateEd25519KeyPair().getPrivate());
        refused(forged, root(NOW + 1000), "keyring", "does not verify");
    }

    @Test
    void pinnedRefusesAnyMemberThatDoesNotVerifyOrIsNotCurrent() {
        KeyringFile forged = KeyringFile.sign(SERVICES, PIN, NOW + 1000, Crypto.generateEd25519KeyPair().getPrivate());
        SignedRoot forgedRoot = SignedRoot.sign(ROOT, "v1", NOW + 1000, Crypto.generateEd25519KeyPair().getPrivate());
        List<SignedRoot> good = List.of(root(NOW + 1000));
        refused(List.of(ring(NOW + 1000), forged), good, "keyrings[1]", "does not verify");
        refused(List.of(ring(NOW + 1000), ring(NOW - 1)), good, "keyrings[1]", "expired", Long.toString(NOW - 1));
        refused(List.of(ring(NOW - 1), ring(NOW + 1000)), good, "keyrings[0]", "expired");
        List<KeyringFile> rings = List.of(ring(NOW + 1000));
        refused(rings, List.of(root(NOW + 1000), forgedRoot), "roots[1]", "does not verify");
        refused(rings, List.of(root(NOW + 1000), root(NOW - 1)), "roots[1]", "expired", Long.toString(NOW - 1));
        refused(rings, List.of(root(NOW - 1), root(NOW + 1000)), "roots[0]", "expired");
        refused(List.of(), good, "keyrings");
        refused(rings, List.of(), "roots");
    }

    @Test
    void pinnedTakesTheEarlierOfTheLatestWindows() {
        VerifierConfig cfg = pinned(List.of(ring(NOW + 1000), ring(NOW + 3000)),
                List.of(root(NOW + 2000), root(NOW + 500)), NOW);
        assertEquals(NOW + 2000, cfg.policyNotAfter());
        assertEquals(List.of(NOW + 1000, NOW + 3000), cfg.keyrings().stream().map(PinnedKeyring::notAfter).toList());
        assertEquals(List.of(NOW + 2000, NOW + 500), cfg.roots().stream().map(PinnedRoot::notAfter).toList());
        assertEquals(NOW + 3000, pinned(List.of(ring(NOW + 3000), ring(NOW + 1000)),
                List.of(root(NOW + 5000)), NOW).policyNotAfter());
        Keyring keys = Keyring.of(Map.of());
        assertEquals(7, VerifierConfig.policyNotAfter(List.of(new PinnedKeyring(keys, 9), new PinnedKeyring(keys, 7)),
                List.of(new PinnedRoot(ROOT, "v1", 7))));
        assertEquals(5, VerifierConfig.policyNotAfter(List.of(new PinnedKeyring(keys, 9)),
                List.of(new PinnedRoot(ROOT, "v1", 2), new PinnedRoot(ROOT, "v2", 5))));
    }

    /** A config pins at least one keyring and one root and no null member, refused when built, as the pin is. */
    @Test
    void aConfigRefusesNoMembersOrANullOne() {
        PinnedKeyring ring = new PinnedKeyring(Keyring.of(Map.of()), NOW);
        PinnedRoot root = new PinnedRoot(ROOT, "v1", NOW);
        assertThrows(IllegalArgumentException.class, () -> config(List.of(), List.of(root)));
        assertThrows(IllegalArgumentException.class, () -> config(List.of(ring), List.of()));
        assertThrows(NullPointerException.class, () -> config(null, List.of(root)));
        assertThrows(NullPointerException.class, () -> config(List.of(ring), null));
        assertThrows(NullPointerException.class, () -> config(Arrays.asList(ring, null), List.of(root)));
        assertThrows(NullPointerException.class, () -> config(List.of(ring), Arrays.asList(null, root)));
        assertThrows(NullPointerException.class, () -> new PinnedKeyring(null, NOW));
        assertThrows(NullPointerException.class, () -> new PinnedRoot(null, "v1", NOW));
        assertThrows(NullPointerException.class, () -> new PinnedRoot(ROOT, null, NOW));
        assertThrows(IllegalArgumentException.class, () -> VerifierConfig.policyNotAfter(List.of(), List.of(root)));
        assertThrows(IllegalArgumentException.class, () -> VerifierConfig.policyNotAfter(List.of(ring), List.of()));
    }

    /** The lists and a root's bytes are copied in and out, so no caller changes what a verifier holds. */
    @Test
    void aConfigCopiesWhatItPins() {
        List<PinnedKeyring> rings = new ArrayList<>(List.of(new PinnedKeyring(Keyring.of(Map.of()), NOW)));
        byte[] bytes = new byte[32];
        PinnedRoot root = new PinnedRoot(bytes, "v1", NOW);
        List<PinnedRoot> roots = new ArrayList<>(List.of(root));
        VerifierConfig cfg = config(rings, roots);
        rings.clear();
        roots.clear();
        bytes[0] = 1;
        root.root()[1] = 1;
        assertEquals(1, cfg.keyrings().size());
        assertEquals(1, cfg.roots().size());
        assertArrayEquals(new byte[32], cfg.roots().get(0).root());
    }

    private static VerifierConfig config(List<PinnedKeyring> keyrings, List<PinnedRoot> roots) {
        return new VerifierConfig(keyrings, roots, NOW, Set.of("session"), "s", new InMemoryNonceCache(), () -> NOW,
                5000, 5000);
    }

    @Test
    void aNonceCacheRemembersForAtLeastTwiceTheCallWindow() {
        assertEquals(VerifierConfig.NONCE_TTL_MS, VerifierConfig.nonceTtlFor(VerifierConfig.CALL_MAX_AGE_MS));
        assertEquals(VerifierConfig.NONCE_TTL_MS, VerifierConfig.nonceTtlFor(0));
        assertEquals(60_000, VerifierConfig.nonceTtlFor(30_000));
        assertEquals(VerifierConfig.NONCE_TTL_MS, VerifierConfig.nonceTtlFor(Long.MIN_VALUE));
        assertEquals(VerifierConfig.NONCE_TTL_MS, VerifierConfig.nonceTtlFor(-1));
        assertEquals(VerifierConfig.NONCE_TTL_MS, VerifierConfig.nonceTtlFor(7_500));
        assertEquals(15_002, VerifierConfig.nonceTtlFor(7_501));
        assertEquals(20_000, VerifierConfig.nonceTtlFor(10_000));
        assertEquals(Long.MAX_VALUE - 1, VerifierConfig.nonceTtlFor(Long.MAX_VALUE / 2));
        assertEquals(Long.MAX_VALUE, VerifierConfig.nonceTtlFor(Long.MAX_VALUE / 2 + 1));
        assertEquals(Long.MAX_VALUE, VerifierConfig.nonceTtlFor(Long.MAX_VALUE));
    }
}
