// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Which requests an unsafe session may not make: by method and dispatched path pattern. */
class UnsafeEndpointsTest {

    private final UnsafeEndpoints endpoints = new UnsafeEndpoints(List.of("POST /refund", "GET /cards/{id}"));

    @Test
    void anEndpointIsTheMethodAndThePathPattern() {
        assertTrue(endpoints.refuses("POST", "/refund"));
        assertTrue(endpoints.refuses("GET", "/cards/{id}"));
        assertFalse(endpoints.refuses("GET", "/refund"), "another method on the same path pattern");
        assertFalse(endpoints.refuses("POST", "/cards/{id}"));
        assertFalse(endpoints.refuses("POST", "/refunds"));
    }

    // The pattern is the dispatched handler's, so a path the caller wrote that is not the pattern is not matched.
    @Test
    void thePatternIsMatchedAsWrittenNotAsAPath() {
        assertFalse(endpoints.refuses("GET", "/cards/7"));
        assertFalse(endpoints.refuses("POST", "/refund;x=1"));
    }

    @Test
    void aHeadIsRefusedWhereItsGetIs() {
        assertTrue(endpoints.refuses("HEAD", "/cards/{id}"));
        assertFalse(endpoints.refuses("HEAD", "/refund"), "no GET /refund is switched off");
    }

    @Test
    void theListIsFixedWhenMade() {
        List<String> disabled = new ArrayList<>(List.of("POST /refund"));
        UnsafeEndpoints fixed = new UnsafeEndpoints(disabled);
        disabled.clear();

        assertTrue(fixed.refuses("POST", "/refund"));
        assertThrows(UnsupportedOperationException.class, () -> fixed.disabled().add("POST /x"));
    }
}
