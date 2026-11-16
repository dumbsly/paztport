// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * Rules 2 to 4 of the signature rule (spec wire.md, Signatures), checked on the bytes before the JDK verifies.
 * Rules 2 and 3 are RFC 8032's own, though not every library makes them, and the RFC leaves refusing a point of small
 * order to the verifier. The three SDKs make the same checks whatever their library already refuses, so on these
 * bytes their answers do not depend on the library. {@code spec/vectors/ed25519.json} pins them.
 */
final class Ed25519Strict {

    /** The group order L = 2^252 + 27742317777372353535851937790883648493. */
    private static final byte[] L = littleEndian("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

    /** The field prime p = 2^255 - 19. */
    private static final byte[] P = littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

    /**
     * The y of every point of small order, ascending: 0 (order 4), 1 (the identity), y8 and p - y8 (order 8), p - 1
     * (order 2). Testing y alone also refuses the encodings of x = 0 that set the sign bit, which RFC 8032 decoding
     * refuses anyway.
     */
    static final byte[][] SMALL_ORDER_Y = {
        littleEndian("0000000000000000000000000000000000000000000000000000000000000000"),
        littleEndian("0000000000000000000000000000000000000000000000000000000000000001"),
        littleEndian("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826"),
        littleEndian("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7"),
        littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
    };

    private Ed25519Strict() {
    }

    /**
     * Rules 2 to 4 for the key {@code a} (32 bytes) and {@code signature} (64 bytes): S below L, then R and A
     * canonical and not of small order. Any other length is false.
     */
    static boolean encodings(byte[] a, byte[] signature) {
        if (a.length != 32 || signature.length != 64) {
            return false;
        }
        byte[] s = new byte[32];
        byte[] r = new byte[32];
        System.arraycopy(signature, 32, s, 0, 32);
        System.arraycopy(signature, 0, r, 0, 32);
        return below(s, L) && strictPoint(r) && strictPoint(a);
    }

    /** 32 little-endian bytes from hex written most significant digit first, so the constants read as the numbers they are. */
    private static byte[] littleEndian(String hex) {
        byte[] b = HexFormat.of().parseHex(hex);
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = b[b.length - 1 - i];
        }
        return out;
    }

    /** True when the little-endian {@code a} is below the little-endian {@code b}, both 32 bytes. Bytes are unsigned here. */
    private static boolean below(byte[] a, byte[] b) {
        for (int i = 31; i >= 0; i--) {
            int x = a[i] & 0xff;
            int y = b[i] & 0xff;
            if (x != y) {
                return x < y;
            }
        }
        return false;
    }

    /** A point's encoding is canonical and not of small order: its y, the sign bit cleared, is below p and not a small-order y. */
    private static boolean strictPoint(byte[] encoding) {
        byte[] y = encoding.clone();
        y[31] &= 0x7f;
        if (!below(y, P)) {
            return false;
        }
        for (byte[] small : SMALL_ORDER_Y) {
            if (Arrays.equals(y, small)) {
                return false;
            }
        }
        return true;
    }
}
