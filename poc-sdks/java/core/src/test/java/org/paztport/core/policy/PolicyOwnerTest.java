// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.session.ReplyCert;

class PolicyOwnerTest {

    private static final long OLD = 1_000L;
    private static final long NEW = 4_102_444_800_000L;

    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final KeyPair other = Crypto.generateEd25519KeyPair();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static Map<String, String> services() {
        return Map.of("orders", pub(Crypto.generateEd25519KeyPair()));
    }

    private KeyringFile ring(KeyPair named, KeyPair signer, long notAfter) {
        return KeyringFile.sign(services(), pub(named), notAfter, signer.getPrivate());
    }

    @Test
    void renewsAKeyringInTheNewFormEvenWhenOldFormOrExpired() {
        KeyringFile expired = ring(policy, policy, OLD);
        KeyringFile oldForm = KeyringFile.signOldForm(services(), pub(policy), policy.getPrivate());

        for (KeyringFile ring : List.of(expired, oldForm)) {
            KeyringFile renewed = PolicyOwner.renewKeyring(ring, NEW, policy.getPrivate());
            assertTrue(renewed.isNewForm());
            assertEquals(NEW, renewed.notAfter());
            assertEquals(ring.services(), renewed.services());
            assertTrue(renewed.verifies(pub(policy)));
        }
    }

    @Test
    void refusesAKeyringThatDoesNotVerifyUnderTheKeyItNames() {
        KeyringFile signed = ring(policy, policy, NEW);
        KeyringFile tampered = new KeyringFile(services(), signed.policy(), signed.sig(), signed.notAfter());
        KeyringFile unsigned = new KeyringFile(signed.services(), signed.policy(), null);

        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.renewKeyring(tampered, NEW, policy.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.renewKeyring(unsigned, NEW, policy.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.renewKeyring(ring(other, other, NEW), NEW, policy.getPrivate()));
    }

    @Test
    void renewsARootOnlyIfThisKeySignedIt() {
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4, OLD,
                policy.getPrivate());

        SignedRoot renewed = PolicyOwner.renewRoot(built.signedRoot(), pub(policy), NEW, policy.getPrivate());

        assertEquals(built.signedRoot().rootId(), renewed.rootId());
        assertEquals(built.signedRoot().root(), renewed.root());
        assertEquals(NEW, renewed.notAfter());
        assertTrue(renewed.verify(policy.getPublic()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.renewRoot(built.signedRoot(), pub(other), NEW, other.getPrivate()));
    }

    @Test
    void issuesAReplyCertOnlyForTheKeyTheKeyringHolds() {
        KeyringFile ring = ring(policy, policy, NEW);

        ReplyCert cert = PolicyOwner.issueReplyCert(ring, "orders", NEW, policy.getPrivate());

        assertEquals(ring.services().get("orders"), cert.key());
        assertEquals("orders", cert.svc());
        assertTrue(cert.verifies(pub(policy)));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.issueReplyCert(ring, "payment", NEW, policy.getPrivate()));
    }

    @Test
    void refusesACertFromAKeyringThatDoesNotVerifyOrIsAnotherKeys() {
        KeyringFile signed = ring(policy, policy, NEW);
        KeyringFile tampered = new KeyringFile(services(), signed.policy(), signed.sig(), signed.notAfter());

        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.issueReplyCert(tampered, "orders", NEW, policy.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.issueReplyCert(ring(other, other, NEW), "orders", NEW, policy.getPrivate()));
    }
}
