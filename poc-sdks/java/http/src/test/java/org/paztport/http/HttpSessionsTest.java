// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The handshake's refusal body: a fixed error shape. */
class HttpSessionsTest {

    @Test
    void errorBody() {
        assertArrayEquals("{\"error\":\"NO_SESSION\"}".getBytes(StandardCharsets.UTF_8),
                HttpSessions.error(HttpSessions.NO_SESSION));
    }
}
