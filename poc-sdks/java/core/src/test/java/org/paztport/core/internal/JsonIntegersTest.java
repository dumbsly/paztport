// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.node.DecimalNode;
import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

class JsonIntegersTest {

    private static Long read(String decimal) {
        return JsonIntegers.safeInteger(DecimalNode.valueOf(new BigDecimal(decimal)));
    }

    @Test
    void readsAnIntegerByItsValue() {
        assertEquals(1L, read("1.0"));
        assertEquals(1000L, read("1E+3"));
        assertEquals(-5L, read("-5.000"));
        assertEquals(9007199254740991L, read("9007199254740991"));
    }

    @Test
    void aZeroWithTrailingZerosReadsAsZero() {
        assertEquals(0L, read("0.000"));
        assertEquals(0L, read("0E+5"));
        assertEquals(0L, read("0"));
    }

    @Test
    void refusesAFractionAndAnIntegerPastTheRange() {
        assertNull(read("9007199254740991.4"));
        assertNull(read("9007199254740992"));
        assertNull(read("1.5"));
    }

    @Test
    void refusesHugeExponentsWithoutBuildingThem() {
        // precision minus scale is 2^31 here, which overflows an int
        assertNull(read("1E+2147483647"));
        assertNull(read("1E+999999999"));
        assertNull(read("1E-2147483647"));
    }
}
