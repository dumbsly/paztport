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
 * SHA-256 and Ed25519 through the JDK's standard cryptography API, with no
 * library of the SDK's own. No shared secrets; verifiers need only public keys.
 * Ed25519 alone names the JDK's own provider, SunEC: providers differ on which
 * signatures verify (Bouncy Castle, say, checks the cofactored equation), and
 * every SDK must answer the same. A JDK without SunEC fails closed. SHA-256 comes
 * from whichever provider the application prefers, since its result does not
 * depend on the provider.
 */
public final class Crypto {

    private static final String ED25519 = "Ed25519";
    /** The JDK's provider of Ed25519, which checks the cofactorless equation the signature rule requires. */
    private static final String ED25519_PROVIDER = "SunEC";
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
            return KeyPairGenerator.getInstance(ED25519, ED25519_PROVIDER).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ED25519, ED25519_PROVIDER);
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /**
     * Verifies a signature. Returns false, and never throws, for any input that
     * does not verify, so callers can fail closed on a boolean. The key must be
     * an Ed25519 X.509 SPKI and the encodings must pass {@link Ed25519Strict}
     * before the JDK's SunEC checks the equation: libraries differ on those
     * bytes, and every SDK refuses the same ones.
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (key == null || message == null || signature == null) {
            return false;
        }
        byte[] spki = key.getEncoded();
        if (!isEd25519Spki(spki) || !Ed25519Strict.encodings(Arrays.copyOfRange(spki, 12, 44), signature)) {
            return false;
        }
        try {
            Signature s = Signature.getInstance(ED25519, ED25519_PROVIDER);
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
     * Decodes an Ed25519 public key. The bytes are checked as they arrive: the JDK accepts the SPKI's length written
     * in long form (45 bytes) and re-encodes it canonically, so checking only its re-encoding would accept a key the
     * other SDKs refuse.
     */
    public static PublicKey decodePublicKey(byte[] x509) {
        if (!isEd25519Spki(x509)) {
            throw new IllegalArgumentException("invalid Ed25519 public key: not the 44-byte Ed25519 SPKI");
        }
        try {
            return KeyFactory.getInstance(ED25519, ED25519_PROVIDER).generatePublic(new X509EncodedKeySpec(x509));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    public static byte[] encodePrivateKey(PrivateKey key) {
        return key.getEncoded();
    }

    public static PrivateKey decodePrivateKey(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance(ED25519, ED25519_PROVIDER).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 private key", e);
        }
    }
}
