// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * {@link Ed25519Strict#encodings} on its own, at the boundaries of rules 2 to 4. SunEC refuses most of these bytes
 * too, so the vector replay alone cannot show the check makes them. Every row is built from integers written here,
 * not from the class's constants, so the test also pins L and p. The TypeScript and Go SDKs carry the same rows.
 */
class Ed25519StrictTest {

    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger L = TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger P = TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger Y8 =
            new BigInteger("55188659117513257062467267217118295137698188065244968500265048394206261417927");
    /** A y that no rule refuses, for the point a row is not about. */
    private static final BigInteger MID = TWO.pow(254);

    private record Row(String name, byte[] a, byte[] signature, boolean want) {
    }

    @Test
    void hasEveryRow() {
        assertEquals(35, rows().size());
    }

    @TestFactory
    Stream<DynamicTest> everyRowGivesItsAnswer() {
        return rows().stream().map(row -> DynamicTest.dynamicTest(row.name(),
                () -> assertEquals(row.want(), Ed25519Strict.encodings(row.a(), row.signature()))));
    }

    private static List<Row> rows() {
        byte[] fine = point(MID, 0);
        List<Row> out = new ArrayList<>();
        out.add(new Row("S = L - 1", fine, signature(fine, L.subtract(BigInteger.ONE)), true));
        out.add(new Row("S = L", fine, signature(fine, L), false));
        out.add(new Row("S with bit 255 set", fine, signature(fine, BigInteger.ONE.setBit(255)), false));
        BigInteger pMinus2 = P.subtract(TWO);
        for (int sign = 0; sign <= 1; sign++) {
            out.add(new Row("R with y = p - 2, sign " + sign, fine, signature(point(pMinus2, sign), BigInteger.ONE),
                    true));
            out.add(new Row("A with y = p - 2, sign " + sign, point(pMinus2, sign), signature(fine, BigInteger.ONE),
                    true));
        }
        String[] nonCanonical = {"p", "2^255 - 1"};
        BigInteger[] nonCanonicalY = {P, TWO.pow(255).subtract(BigInteger.ONE)};
        for (int i = 0; i < nonCanonical.length; i++) {
            out.add(new Row("R with y = " + nonCanonical[i], fine,
                    signature(point(nonCanonicalY[i], 0), BigInteger.ONE), false));
            out.add(new Row("A with y = " + nonCanonical[i], point(nonCanonicalY[i], 0),
                    signature(fine, BigInteger.ONE), false));
        }
        String[] small = {"0", "1", "p - 1", "y8", "p - y8"};
        BigInteger[] smallY = {BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE), Y8, P.subtract(Y8)};
        for (int i = 0; i < small.length; i++) {
            for (int sign = 0; sign <= 1; sign++) {
                out.add(new Row("R with y = " + small[i] + ", sign " + sign, fine,
                        signature(point(smallY[i], sign), BigInteger.ONE), false));
                out.add(new Row("A with y = " + small[i] + ", sign " + sign, point(smallY[i], sign),
                        signature(fine, BigInteger.ONE), false));
            }
        }
        byte[] sig = signature(fine, BigInteger.ONE);
        out.add(new Row("a key of 31 bytes", Arrays.copyOf(fine, 31), sig, false));
        out.add(new Row("a key of 33 bytes", Arrays.copyOf(fine, 33), sig, false));
        out.add(new Row("a signature of 63 bytes", fine, Arrays.copyOf(sig, 63), false));
        out.add(new Row("a signature of 65 bytes", fine, Arrays.copyOf(sig, 65), false));
        return out;
    }

    /** {@code n} as 32 little-endian bytes. */
    private static byte[] le32(BigInteger n) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = n.shiftRight(8 * i).byteValue();
        }
        return out;
    }

    /** A point's encoding: y little-endian, the sign bit in the top bit of the last byte. */
    private static byte[] point(BigInteger y, int sign) {
        return le32(sign == 1 ? y.setBit(255) : y);
    }

    private static byte[] signature(byte[] r, BigInteger s) {
        byte[] out = Arrays.copyOf(r, 64);
        System.arraycopy(le32(s), 0, out, 32, 32);
        return out;
    }
}
