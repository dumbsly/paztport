// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.OwnMaterial.Kind;
import org.paztport.core.policy.OwnMaterial.Problem;
import org.paztport.core.policy.OwnMaterial.Subject;

/** What a service may start with, and when it is told its material is about to end. */
class OwnMaterialTest {

    private static final long NOW = 1_800_000_000_000L;
    private static final long HOUR = 3_600_000L;
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final String PIN = Base64Url.encode(Crypto.encodePublicKey(POLICY.getPublic()));
    private static final Map<String, String> SERVICES = Map.of("session", PIN);

    private static KeyringFile ring(long notAfter) {
        return KeyringFile.sign(SERVICES, PIN, notAfter, POLICY.getPrivate());
    }

    private static SignedRoot root(long notAfter) {
        return SignedRoot.sign(new byte[32], "v1", notAfter, POLICY.getPrivate());
    }

    @Test
    void currentMaterialThatVerifiesHasNoProblem() {
        assertEquals(List.of(), OwnMaterial.check(ring(NOW + 100 * HOUR), root(NOW + 100 * HOUR), PIN, NOW));
    }

    @Test
    void reportsEachProblemInTheOrderACallerShouldRaiseThem() {
        KeyPair stranger = Crypto.generateEd25519KeyPair();
        KeyringFile forged = KeyringFile.sign(SERVICES, PIN, NOW - 1, stranger.getPrivate());
        SignedRoot forgedRoot = SignedRoot.sign(new byte[32], "v1", NOW - 2, stranger.getPrivate());
        assertEquals(List.of(
                new Problem(Subject.KEYRING, Kind.DOES_NOT_VERIFY, null),
                new Problem(Subject.ROOT, Kind.DOES_NOT_VERIFY, null),
                new Problem(Subject.KEYRING, Kind.EXPIRED, NOW - 1),
                new Problem(Subject.ROOT, Kind.EXPIRED, NOW - 2)),
                OwnMaterial.check(forged, forgedRoot, PIN, NOW));
    }

    @Test
    void aRootThatDoesNotVerifyIsAProblemEvenWithAGarbagePin() {
        assertEquals(List.of(new Problem(Subject.ROOT, Kind.DOES_NOT_VERIFY, null)),
                OwnMaterial.check(ring(NOW + HOUR), SignedRoot.sign(new byte[32], "v1", NOW + HOUR,
                        Crypto.generateEd25519KeyPair().getPrivate()), PIN, NOW));
        assertTrue(OwnMaterial.check(ring(NOW + HOUR), root(NOW + HOUR), "!", NOW).stream()
                .anyMatch(p -> p.subject() == Subject.ROOT && p.kind() == Kind.DOES_NOT_VERIFY));
    }

    @Test
    void warnsOfWhatEndsWithinFortyTwoHoursAndNoOtherThing() {
        assertEquals(42 * HOUR, OwnMaterial.WARN_WITHIN_MS);
        assertEquals(List.of(Subject.KEYRING), OwnMaterial.expiringSoon(
                ring(NOW + OwnMaterial.WARN_WITHIN_MS), root(NOW + OwnMaterial.WARN_WITHIN_MS + 1), NOW));
        assertEquals(List.of(Subject.KEYRING, Subject.ROOT), OwnMaterial.expiringSoon(ring(NOW), root(NOW), NOW));
        // Already over: a problem, not a warning.
        assertEquals(List.of(), OwnMaterial.expiringSoon(ring(NOW - 1), root(NOW - 1), NOW));
    }

    @Test
    void describesAnyNotAfterWithoutThrowing() {
        assertTrue(OwnMaterial.describe(Long.MAX_VALUE).startsWith("9223372036854775807"));
        assertTrue(OwnMaterial.describe(KeyringFile.MAX_NOT_AFTER).startsWith("9007199254740991 ("));
    }
}
