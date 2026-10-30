// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * The partner's startup checks on its own material, as the builder makes them for any framework: each fault it
 * refuses, in its order, and what it defaults. The starter's words for each are tested with its configuration.
 */
class PartnerSessionsBuilderTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;
    private static final long WEEK = 7 * 86_400_000L;

    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final KeyPair key = Crypto.generateEd25519KeyPair();
    private final KeyringFile keyring = KeyringFile.sign(Map.of("psp", pub(key)), pub(policy), NOT_AFTER,
            policy.getPrivate());
    private final SignedRoot root = PolicyBuilder.build(List.of(List.of("psp", "x")), 4, NOT_AFTER,
            policy.getPrivate()).signedRoot();
    private final long now = System.currentTimeMillis();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private ReplyCert cert(String service, KeyPair certified, long notAfter, KeyPair signer) {
        return ReplyCert.issue(pub(policy), service, pub(certified), notAfter, signer.getPrivate());
    }

    /** Everything a partner needs, all of it sound. */
    private PartnerSessions.Builder sound() {
        return PartnerSessions.builder()
                .ownRoot(root)
                .ownKeyring(keyring)
                .ownPolicyKey(pub(policy))
                .ownService("psp")
                .ownServiceKey(key.getPrivate())
                .ownReplyCert(cert("psp", key, now + WEEK, policy))
                .pinnedClientKeys(Set.of(pub(Crypto.generateEd25519KeyPair())))
                .clientOrigins(Set.of("payment"))
                .clock(() -> now)
                .callMaxAgeMs(5000);
    }

    private static PartnerSessions.Fault fault(PartnerSessions.Builder builder) {
        return assertThrows(PartnerSessions.InvalidMaterial.class, builder::build).fault();
    }

    @Test
    void soundMaterialBuildsWithTheDefaults() {
        PartnerSessions sessions = sound().build();

        assertEquals(List.of(), sessions.unsafeOperations().disabled());
        assertNotNull(sessions.open(SessionRequest.of(null, pub(policy), keyring, Sessions.newNonce()),
                "CN=shop CA", "orders"));
        assertEquals(16, PartnerSessions.DEFAULT_MAX_SESSIONS_PER_PEER);
        assertEquals(900_000, PartnerSessions.DEFAULT_SESSION_IDLE_MS);
    }

    @Test
    void ownMaterialMustVerifyUnderThePinAndBeCurrent() {
        KeyPair other = Crypto.generateEd25519KeyPair();
        assertEquals(PartnerSessions.Fault.OWN_MATERIAL, fault(sound().ownPolicyKey(pub(other))));
        assertEquals(PartnerSessions.Fault.OWN_MATERIAL, fault(sound().ownKeyring(
                KeyringFile.sign(Map.of("psp", pub(key)), pub(policy), now - 1, policy.getPrivate()))));
        assertEquals(PartnerSessions.Fault.OWN_MATERIAL, fault(sound().ownRoot(
                SignedRoot.signOldForm(root.rootBytes(), root.rootId(), policy.getPrivate()))));
    }

    @Test
    void theKeyringMustHoldTheEntryServicesKey() {
        assertEquals(PartnerSessions.Fault.NO_ENTRY_KEY, fault(sound().ownService("ledger")));
        assertEquals(PartnerSessions.Fault.KEY_MISMATCH,
                fault(sound().ownServiceKey(Crypto.generateEd25519KeyPair().getPrivate())));
    }

    @Test
    void theReplyCertificateMustVerifyNameTheServiceAndItsKeyAndBeCurrent() {
        KeyPair other = Crypto.generateEd25519KeyPair();
        assertEquals(PartnerSessions.Fault.CERT_UNVERIFIED, fault(sound().ownReplyCert(cert("psp", key,
                now + WEEK, other))));
        assertEquals(PartnerSessions.Fault.CERT_WRONG_SERVICE, fault(sound().ownReplyCert(cert("ledger", key,
                now + WEEK, policy))));
        assertEquals(PartnerSessions.Fault.CERT_WRONG_KEY, fault(sound().ownReplyCert(cert("psp", other,
                now + WEEK, policy))));
        assertEquals(PartnerSessions.Fault.CERT_EXPIRED, fault(sound().ownReplyCert(cert("psp", key, now - 1,
                policy))));
    }

    // The checks run in the order the javadoc gives, so a partner wrong in two ways hears of the first.
    @Test
    void theFirstFaultIsTheOneNamed() {
        assertEquals(PartnerSessions.Fault.NO_ENTRY_KEY, fault(sound().ownService("ledger")
                .ownReplyCert(cert("psp", key, now - 1, policy))));
        assertEquals(PartnerSessions.Fault.KEY_MISMATCH, fault(sound()
                .ownServiceKey(Crypto.generateEd25519KeyPair().getPrivate())
                .ownReplyCert(cert("psp", key, now + WEEK, Crypto.generateEd25519KeyPair()))));
    }

    @Test
    void aPartnerNeedsItsMaterialAClientToTrustAndAnOrigin() {
        assertThrows(NullPointerException.class, () -> sound().ownReplyCert(null).build());
        assertThrows(NullPointerException.class, () -> sound().ownServiceKey(null).build());
        IllegalArgumentException noClients = assertThrows(IllegalArgumentException.class,
                () -> sound().pinnedClientKeys(Set.of()).build());
        assertTrue(noClients.getMessage().contains("no client policy key"), noClients.getMessage());
        assertThrows(IllegalArgumentException.class, () -> sound().clientOrigins(Set.of()).build());
        assertThrows(IllegalArgumentException.class, () -> sound().maxSessionsPerPeer(0).build());
        assertThrows(IllegalArgumentException.class, () -> sound().sessionIdleMs(0).build());
    }

    @Test
    void theOperationsSwitchedOffAreTheOnesTheRepliesList() {
        PartnerSessions sessions = sound().unsafeDisabled(List.of("POST /refund")).build();

        assertEquals(List.of("POST /refund"), sessions.unsafeOperations().disabled());
        assertTrue(sessions.unsafeOperations().refuses("POST", "/refund"));
    }
}
