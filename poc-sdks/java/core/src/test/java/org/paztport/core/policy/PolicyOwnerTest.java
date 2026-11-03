// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
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
    void renewsAKeyringEvenWhenExpired() {
        KeyringFile expired = ring(policy, policy, OLD);

        KeyringFile renewed = PolicyOwner.renewKeyring(expired, NEW, policy.getPrivate());
        assertEquals(NEW, renewed.notAfter());
        assertEquals(expired.services(), renewed.services());
        assertTrue(renewed.verifies(pub(policy)));
    }

    @Test
    void refusesAKeyringThatDoesNotVerifyUnderTheKeyItNames() {
        KeyringFile signed = ring(policy, policy, NEW);
        KeyringFile tampered = new KeyringFile(services(), signed.policy(), signed.sig(), signed.notAfter());
        KeyringFile unsigned = new KeyringFile(signed.services(), signed.policy(), null, signed.notAfter());

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
    void refusesToRenewARootWithAPrivateKeyThatIsNotThePolicyKeysOwn() {
        SignedRoot root = SignedRoot.sign(new byte[32], "root-1", OLD, policy.getPrivate());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.renewRoot(root, pub(policy), NEW, other.getPrivate()));
        assertEquals("root is not signed by this policy key", e.getMessage());
    }

    @Test
    void refusesToRenewARootAgainstAMalformedPolicyKey() {
        SignedRoot root = SignedRoot.sign(new byte[32], "root-1", OLD, policy.getPrivate());

        for (String key : Arrays.asList(null, "", "not base64url!", Base64Url.encode(new byte[12]))) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PolicyOwner.renewRoot(root, key, NEW, policy.getPrivate()));
            assertTrue(e.getMessage().startsWith("root "), e.getMessage());
        }
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

    @Test
    void rotateKeyringReplacesOnlyTheNamedServicesKey() {
        String orders = pub(Crypto.generateEd25519KeyPair());
        String gateway = pub(Crypto.generateEd25519KeyPair());
        KeyringFile current = KeyringFile.sign(Map.of("orders", orders, "gateway", gateway), pub(policy), OLD,
                policy.getPrivate());
        KeyPair fresh = Crypto.generateEd25519KeyPair();

        KeyringFile rotated = PolicyOwner.rotateKeyring(current, "orders", fresh.getPublic(), NEW,
                policy.getPrivate());

        assertEquals(Map.of("orders", pub(fresh), "gateway", gateway), rotated.services());
        assertEquals(pub(policy), rotated.policy());
        assertEquals(NEW, rotated.notAfter());
        assertTrue(rotated.verifies(pub(policy)));
    }

    @Test
    void rotateKeyringRefusesAKeyringTheKeyDidNotSign() {
        PublicKey fresh = Crypto.generateEd25519KeyPair().getPublic();
        KeyringFile signed = ring(policy, policy, NEW);
        KeyringFile tampered = new KeyringFile(services(), signed.policy(), signed.sig(), signed.notAfter());

        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.rotateKeyring(tampered, "orders", fresh, NEW, policy.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.rotateKeyring(ring(other, other, NEW), "orders", fresh, NEW, policy.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> PolicyOwner.rotateKeyring(ring(policy, policy, NEW),
                "orders", fresh, KeyringFile.MAX_NOT_AFTER + 1, policy.getPrivate()));
    }

    @Test
    void rotateKeyringRefusesAServiceTheKeyringDoesNotName() {
        PublicKey fresh = Crypto.generateEd25519KeyPair().getPublic();

        assertThrows(IllegalArgumentException.class,
                () -> PolicyOwner.rotateKeyring(ring(policy, policy, NEW), "payment", fresh, NEW,
                        policy.getPrivate()));
    }
}
