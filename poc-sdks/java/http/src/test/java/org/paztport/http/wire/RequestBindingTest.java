// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class RequestBindingTest {

    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    @Test
    void isDeterministicForSameRequest() {
        assertEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/pay", BODY));
    }

    @Test
    void changesWhenMethodChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("GET", "/pay", BODY));
    }

    @Test
    void changesWhenPathChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/refund", BODY));
    }

    @Test
    void changesWhenBodyChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/pay", "{\"amount\":200}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void isBase64UrlOfASha256() {
        // 32-byte digest -> 43 unpadded base64url chars.
        assertEquals(43, RequestBinding.compute("POST", "/pay", BODY).length());
    }
}
