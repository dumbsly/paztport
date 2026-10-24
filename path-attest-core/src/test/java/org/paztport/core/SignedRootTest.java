// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class SignedRootTest {

    @Test
    void signedRootVerifiesWithPolicyPublicKey() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        byte[] root = Crypto.sha256("root".getBytes());

        SignedRoot signed = SignedRoot.sign(root, "v1", policy.getPrivate());

        assertTrue(signed.verify(policy.getPublic()));
        assertArrayEquals(root, signed.rootBytes());
        assertEquals("v1", signed.rootId());
    }

    @Test
    void verifyFailsWithWrongPolicyKey() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair attacker = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        assertFalse(signed.verify(attacker.getPublic()));
    }

    @Test
    void verifyFailsWhenRootTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot forged = new SignedRoot(
                signed.rootId(), Base64Url.encode(Crypto.sha256("evil".getBytes())), signed.sig());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void verifyFailsWhenRootIdTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot forged = new SignedRoot("v2", signed.root(), signed.sig());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void encodeDecodeRoundTrips() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot decoded = SignedRoot.decode(signed.encode());
        assertEquals(signed, decoded);
        assertTrue(decoded.verify(policy.getPublic()));
    }
}
