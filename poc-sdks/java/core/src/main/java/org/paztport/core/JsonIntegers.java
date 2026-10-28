// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;

/**
 * The one reading of a wire integer, shared by the stamp {@code v} and {@code ts} and every {@code notAfter}: the
 * reply certificate's, a root's and a keyring's. The TypeScript SDK judges a number by its value, so this does too:
 * were Java to judge the text instead, {@code 1.0} would be accepted by one SDK and refused by the other. Reading
 * alone does not settle a reply's verdict: its signature covers the parsed value, so the client's check also hashes
 * each {@code notAfter} the reply carries as the integer read here (see {@code Sessions}), since {@link Jcs} refuses
 * {@code 1.0}.
 */
final class JsonIntegers {

    /** 2^53 &minus; 1, the largest integer both SDKs read and print the same way. */
    static final long MAX_SAFE = (1L << 53) - 1;

    private JsonIntegers() {
    }

    /**
     * A number's value if it is an integer within &plusmn;(2^53&minus;1), else null; never throws. Checked by value,
     * so {@code 1.0} and {@code 1e3} are the integers 1 and 1000, while a string, a fraction or a larger integer is
     * refused.
     */
    static Long safeInteger(JsonNode n) {
        if (n == null || !n.isNumber()) {
            return null;
        }
        try {
            BigDecimal d = n.isIntegralNumber() ? new BigDecimal(n.bigIntegerValue()) : n.decimalValue();
            long v = d.toBigIntegerExact().longValueExact();
            return Math.abs(v) <= MAX_SAFE ? v : null;
        } catch (ArithmeticException | NumberFormatException e) {
            return null;
        }
    }
}
