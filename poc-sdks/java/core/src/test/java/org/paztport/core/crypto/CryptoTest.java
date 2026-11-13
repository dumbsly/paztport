// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
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
    void verifyIsFalseForAnEmptySignature() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        assertFalse(Crypto.verify(kp.getPublic(), bytes("m"), new byte[0]));
    }

    @Test
    void verifyIsFalseForANullSignature() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        assertFalse(Crypto.verify(kp.getPublic(), bytes("m"), null));
    }

    @Test
    void verifyIsFalseForANullKey() {
        assertFalse(Crypto.verify(null, bytes("m"), new byte[64]));
    }

    @Test
    void verifyIsFalseForANullMessage() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] sig = Crypto.sign(kp.getPrivate(), bytes("m"));
        assertFalse(Crypto.verify(kp.getPublic(), null, sig));
    }

    /**
     * The SDK names the JDK's SunEC for Ed25519, so a JDK without it fails closed: verify answers false and the
     * other methods throw the exceptions they already throw, rather than falling back to whatever provider is left.
     */
    @Test
    void withoutSunEcVerifyIsFalseAndTheRestThrow() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        byte[] msg = bytes("m");
        byte[] sig = Crypto.sign(kp.getPrivate(), msg);
        byte[] spki = Crypto.encodePublicKey(kp.getPublic());
        byte[] pkcs8 = Crypto.encodePrivateKey(kp.getPrivate());
        Provider sunEc = Security.getProvider("SunEC");
        int position = Arrays.asList(Security.getProviders()).indexOf(sunEc) + 1;
        Security.removeProvider("SunEC");
        try {
            assertFalse(Crypto.verify(kp.getPublic(), msg, sig));
            assertThrows(IllegalStateException.class, Crypto::generateEd25519KeyPair);
            assertThrows(IllegalStateException.class, () -> Crypto.sign(kp.getPrivate(), msg));
            assertThrows(IllegalArgumentException.class, () -> Crypto.decodePublicKey(spki));
            assertThrows(IllegalArgumentException.class, () -> Crypto.decodePrivateKey(pkcs8));
        } finally {
            Security.insertProviderAt(sunEc, position);
        }
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
