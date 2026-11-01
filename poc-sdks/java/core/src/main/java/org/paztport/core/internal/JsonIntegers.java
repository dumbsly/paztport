// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import org.paztport.core.encoding.Jcs;

/**
 * The one reading of a wire integer, shared by the stamp {@code v} and {@code ts} and every {@code notAfter}: the
 * reply certificate's, a root's and a keyring's. The TypeScript SDK judges a number by its value, so this does too:
 * were Java to judge the text instead, {@code 1.0} would be accepted by one SDK and refused by the other. Reading
 * alone does not settle a reply's verdict: its signature covers the parsed value, so the client's check also hashes
 * each {@code notAfter} the reply carries as the integer read here (see {@code Sessions}), since {@link Jcs} refuses
 * {@code 1.0}.
 */
public final class JsonIntegers {

    /** 2^53 &minus; 1, the largest integer both SDKs read and print the same way. */
    public static final long MAX_SAFE = (1L << 53) - 1;

    private JsonIntegers() {
    }

    /**
     * A number's value if it is an integer within &plusmn;(2^53&minus;1), else null; never throws. Checked by value,
     * so {@code 1.0} and {@code 1e3} are the integers 1 and 1000, while a string, a fraction or a larger integer is
     * refused.
     */
    public static Long safeInteger(JsonNode n) {
        if (n == null || !n.isNumber()) {
            return null;
        }
        try {
            BigDecimal d = n.isIntegralNumber() ? new BigDecimal(n.bigIntegerValue()) : n.decimalValue();
            // Judged before any integer is built, so that an exponent such as 1e999999999 costs nothing. The
            // digit count is a long, since precision minus a very negative scale overflows an int.
            d = d.stripTrailingZeros();
            if (d.scale() > 0 || (long) d.precision() - d.scale() > 16) {
                return null;
            }
            long v = d.toBigIntegerExact().longValueExact();
            return isSafe(v) ? v : null;
        } catch (ArithmeticException | NumberFormatException e) {
            return null;
        }
    }

    /**
     * True when {@code v} is within &plusmn;(2^53 &minus; 1). Both ends are compared, not {@code Math.abs(v)}:
     * &minus;2^63 has no positive {@code long}, so its absolute value is itself, which is negative, and would pass.
     */
    public static boolean isSafe(long v) {
        return v >= -MAX_SAFE && v <= MAX_SAFE;
    }

    /**
     * True when {@code v} is a protocol integer: in [0, 2^53 &minus; 1]. The one range check every window and every
     * stamp {@code ts} is held to, whether read from the wire, about to be signed or pinned in a verifier's config,
     * so that no value one SDK accepts is one the other refuses.
     */
    public static boolean inRange(long v) {
        return v >= 0 && v <= MAX_SAFE;
    }

    /**
     * A {@code notAfter}'s value when {@code n} is an integer in [0, 2^53 &minus; 1], judged by value as
     * {@link #safeInteger} judges it; else null, never throwing, an absent member ({@code n} null) included. A
     * caller refuses null: every root and keyring carries a window.
     */
    public static Long notAfter(JsonNode n) {
        Long v = safeInteger(n);
        return v != null && inRange(v) ? v : null;
    }
}
