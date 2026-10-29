// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;

class CryptoTest {

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void sha256IsThirtyTwoBytesAndDeterministic() {
        byte[] a = Crypto.sha256(bytes("gateway/orders/payment"));
        byte[] b = Crypto.sha256(bytes("gateway/orders/payment"));
        assertEquals(32, a.length);
        assertArrayEquals(a, b);
    }

    @Test
    void signedMessageVerifiesWithMatchingPublicKey() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] msg = bytes("svc|inst|rid|ts|bind|prev");
        byte[] sig = Crypto.sign(kp.getPrivate(), msg);
        assertTrue(Crypto.verify(kp.getPublic(), msg, sig));
    }

    @Test
    void verifyFailsWhenMessageTampered() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] sig = Crypto.sign(kp.getPrivate(), bytes("original"));
        assertFalse(Crypto.verify(kp.getPublic(), bytes("tampered"), sig));
    }

    @Test
    void verifyFailsWithWrongKey() {
        KeyPair signer = Crypto.generateEd25519KeyPair();
        KeyPair other = Crypto.generateEd25519KeyPair();
        byte[] msg = bytes("message");
        byte[] sig = Crypto.sign(signer.getPrivate(), msg);
        assertFalse(Crypto.verify(other.getPublic(), msg, sig));
    }

    @Test
    void randomBytesHasRequestedLengthAndVaries() {
        byte[] a = Crypto.randomBytes(16);
        byte[] b = Crypto.randomBytes(16);
        assertEquals(16, a.length);
        assertFalse(java.util.Arrays.equals(a, b), "two random draws must differ");
    }

    @Test
    void publicKeyEncodeDecodeRoundTripsAndStillVerifies() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] msg = bytes("message");
        byte[] sig = Crypto.sign(kp.getPrivate(), msg);

        byte[] encoded = Crypto.encodePublicKey(kp.getPublic());
        PublicKey decoded = Crypto.decodePublicKey(encoded);

        assertTrue(Crypto.verify(decoded, msg, sig));
    }

    @Test
    void privateKeyEncodeDecodeRoundTripsAndStillSigns() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] msg = bytes("message");

        byte[] encoded = Crypto.encodePrivateKey(kp.getPrivate());
        java.security.PrivateKey decoded = Crypto.decodePrivateKey(encoded);

        byte[] sig = Crypto.sign(decoded, msg);
        assertTrue(Crypto.verify(kp.getPublic(), msg, sig));
    }
}
