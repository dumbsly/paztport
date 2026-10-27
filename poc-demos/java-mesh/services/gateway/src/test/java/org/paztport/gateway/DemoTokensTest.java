// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.Test;

class DemoTokensTest {

    private final DemoTokens tokens = new DemoTokens(Map.of("alice-token", "alice", "mallory-token", "mallory"));

    @Test
    void knownBearerTokenNamesItsCustomer() {
        assertEquals("alice", tokens.customerFor("Bearer alice-token"));
        assertEquals("mallory", tokens.customerFor("Bearer mallory-token"));
    }

    @Test
    void anythingElseIsNobody() {
        assertNull(tokens.customerFor("Bearer eve-token"));
        assertNull(tokens.customerFor(null));
        assertNull(tokens.customerFor("Basic YWxpY2U6c2VjcmV0"));
        assertNull(tokens.customerFor("Bearer "));
        assertNull(tokens.customerFor("Bearer"));
        assertNull(tokens.customerFor(""));
    }
}
