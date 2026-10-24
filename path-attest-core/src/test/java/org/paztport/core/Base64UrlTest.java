// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Base64UrlTest {

    @Test
    void roundTripsArbitraryBytes() {
        byte[] data = "gateway/orders/payment".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64Url.encode(data);
        assertArrayEquals(data, Base64Url.decode(encoded));
    }

    @Test
    void producesNoPadding() {
        // 1 byte normally encodes to "AA==" in standard base64; we want no '='.
        String encoded = Base64Url.encode(new byte[] {0});
        assertFalse(encoded.contains("="), "encoding must be unpadded");
    }

    @Test
    void usesUrlSafeAlphabet() {
        // 0xFB,0xFF,0xBF forces the standard-alphabet '+' and '/' characters,
        // which must appear as '-' and '_' in the url-safe alphabet.
        String encoded = Base64Url.encode(new byte[] {(byte) 0xFB, (byte) 0xFF, (byte) 0xBF});
        assertEquals("-_-_", encoded);
    }

    @Test
    void decodeRejectsMalformedInput() {
        // '+' and '/' are not part of the url-safe alphabet: fail closed.
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("++//"));
    }
}
