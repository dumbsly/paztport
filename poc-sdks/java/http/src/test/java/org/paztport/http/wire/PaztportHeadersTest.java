// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PaztportHeadersTest {

    @Test
    void everyHeaderUnderThePrefixIsPaztports() {
        for (String name : new String[] {"X-Path-Chain", "x-path-chain", "X-PATH-PROOF", "X-Path-Influence",
                "X-Path-Session", "X-Path-Response", "X-Path-Future", "X-Path-"}) {
            assertTrue(PaztportHeaders.isPaztport(name), name);
        }
    }

    @Test
    void aNameWithoutThePrefixIsNot() {
        for (String name : new String[] {"X-Path", "X-Pathology", "X-Path_Chain", "XX-Path-Chain", "",
                "X‐Path‐Chain", "X-Pаth-Chain"}) {
            assertFalse(PaztportHeaders.isPaztport(name), name);
        }
    }

    @Test
    void nullIsNot() {
        assertFalse(PaztportHeaders.isPaztport(null));
    }
}
