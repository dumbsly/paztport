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
import java.util.Arrays;
import java.util.HexFormat;

/**
 * The only cryptography in the system: SHA-256 and Ed25519, both straight from
 * the JDK. No shared secrets; verifiers need only public keys.
 */
public final class Crypto {

    private static final String ED25519 = "Ed25519";
    /** The X.509 SPKI prefix of an Ed25519 key: the 32 key bytes follow it. */
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
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
     * failure so callers can fail closed on a boolean. The key must be an
     * Ed25519 X.509 SPKI and the encodings must pass {@link Ed25519Strict}
     * before the JDK checks the equation: libraries differ on those bytes, and
     * every SDK refuses the same ones.
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (key == null || signature == null) {
            return false;
        }
        byte[] spki = key.getEncoded();
        if (!isEd25519Spki(spki) || !Ed25519Strict.encodings(Arrays.copyOfRange(spki, 12, 44), signature)) {
            return false;
        }
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

    /** True for exactly the 44 bytes of an Ed25519 SPKI: the fixed prefix, then the 32 key bytes. */
    private static boolean isEd25519Spki(byte[] x509) {
        return x509 != null && x509.length == 44 && Arrays.equals(x509, 0, 12, ED25519_SPKI_PREFIX, 0, 12);
    }

    /**
     * Decodes an Ed25519 public key. The bytes are checked as they arrive: the JDK reads BER leniently (a length in
     * long form, a trailing byte) and re-encodes canonically, so checking only its re-encoding would accept a key
     * the other SDKs refuse.
     */
    public static PublicKey decodePublicKey(byte[] x509) {
        if (!isEd25519Spki(x509)) {
            throw new IllegalArgumentException("invalid Ed25519 public key: not the 44-byte Ed25519 SPKI");
        }
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
