// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/** What {@link VerifierConfigV3#pinned} refuses at build time: a keyring or root in the old form or past its window. */
class VerifierConfigV3Test {

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

    private static VerifierConfigV3 pinned(KeyringFile keyring, SignedRoot root, long now) {
        return VerifierConfigV3.pinned(keyring, root, PIN, Set.of("session"), "s", new InMemoryNonceCache(), () -> now,
                5000, 5000);
    }

    private static void refused(KeyringFile keyring, SignedRoot root, String... words) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> pinned(keyring, root, NOW));
        for (String w : words) {
            assertTrue(e.getMessage().contains(w), e.getMessage() + " should name " + w);
        }
    }

    @Test
    void oldFormKeyringRefusedAtBuild() {
        KeyringFile old = KeyringFile.signOldForm(SERVICES, PIN, POLICY.getPrivate());
        refused(old, root(NOW + 1000), "keyring", "old form");
    }

    @Test
    void oldFormRootRefusedAtBuild() {
        SignedRoot old = SignedRoot.signOldForm(ROOT, "v1", POLICY.getPrivate());
        refused(ring(NOW + 1000), old, "root", "old form");
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
}
