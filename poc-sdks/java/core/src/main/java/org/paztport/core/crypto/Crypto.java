// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * The only cryptography in the system: SHA-256 and Ed25519, both straight from
 * the JDK. No shared secrets; verifiers need only public keys.
 */
public final class Crypto {

    private static final String ED25519 = "Ed25519";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    /** Cryptographically strong random bytes for salts and nonces. */
    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static KeyPair generateEd25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance(ED25519).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ED25519);
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /**
     * Verifies a signature. Returns false (never throws) on any verification
     * failure so callers can fail closed on a boolean.
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            Signature s = Signature.getInstance(ED25519);
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static byte[] encodePublicKey(PublicKey key) {
        return key.getEncoded();
    }

    public static PublicKey decodePublicKey(byte[] x509) {
        try {
            return KeyFactory.getInstance(ED25519).generatePublic(new X509EncodedKeySpec(x509));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    public static byte[] encodePrivateKey(PrivateKey key) {
        return key.getEncoded();
    }

    public static PrivateKey decodePrivateKey(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance(ED25519).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 private key", e);
        }
    }
}
