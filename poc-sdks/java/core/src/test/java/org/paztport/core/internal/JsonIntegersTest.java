// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class JsonIntegersTest {

    @Test
    void aProtocolIntegerIsFromZeroToTwoToTheFiftyThreeLessOne() {
        assertTrue(JsonIntegers.inRange(0));
        assertTrue(JsonIntegers.inRange(9007199254740991L));
        assertFalse(JsonIntegers.inRange(-1));
        assertFalse(JsonIntegers.inRange(9007199254740992L));
        assertFalse(JsonIntegers.inRange(Long.MIN_VALUE));
    }
}
