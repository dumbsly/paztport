// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Which requests an unsafe session may not make: by method and dispatched route pattern. */
class UnsafeOperationsTest {

    private final UnsafeOperations ops = new UnsafeOperations(List.of("POST /refund", "GET /cards/{id}"));

    @Test
    void anOperationIsTheMethodAndTheRoutePattern() {
        assertTrue(ops.refuses("POST", "/refund"));
        assertTrue(ops.refuses("GET", "/cards/{id}"));
        assertFalse(ops.refuses("GET", "/refund"), "another method on the same route");
        assertFalse(ops.refuses("POST", "/cards/{id}"));
        assertFalse(ops.refuses("POST", "/refunds"));
    }

    // The pattern is the dispatched handler's, so a path the caller wrote that is not the pattern is not matched.
    @Test
    void thePatternIsMatchedAsWrittenNotAsAPath() {
        assertFalse(ops.refuses("GET", "/cards/7"));
        assertFalse(ops.refuses("POST", "/refund;x=1"));
    }

    @Test
    void aHeadIsRefusedWhereItsGetIs() {
        assertTrue(ops.refuses("HEAD", "/cards/{id}"));
        assertFalse(ops.refuses("HEAD", "/refund"), "no GET /refund is switched off");
    }

    @Test
    void theListIsFixedWhenMade() {
        List<String> disabled = new ArrayList<>(List.of("POST /refund"));
        UnsafeOperations fixed = new UnsafeOperations(disabled);
        disabled.clear();

        assertTrue(fixed.refuses("POST", "/refund"));
        assertThrows(UnsupportedOperationException.class, () -> fixed.disabled().add("POST /x"));
    }
}
