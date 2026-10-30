// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

class RoutesTest {

    @Test
    void joinsOneTwoAndThreeHopRoutesWithSlashes() {
        assertEquals("gateway", Routes.join(List.of("gateway")));
        assertEquals("gateway/orders", Routes.join(List.of("gateway", "orders")));
        assertEquals("gateway/orders/payment", Routes.join(List.of("gateway", "orders", "payment")));
    }

    @Test
    void refusesAnEmptyNode() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode(""));
    }

    @Test
    void refusesTheDotNodes() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("."));
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode(".."));
    }

    @Test
    void refusesASlash() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("a/b"));
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("/"));
    }

    @Test
    void refusesABackslash() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("a\\b"));
    }

    @Test
    void refusesAPipe() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("a|b"));
    }

    @Test
    void refusesALoneSurrogateInEitherHalfOrPosition() {
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("a\ud800"));
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("\ud800a"));
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("\udc00"));
        assertThrows(IllegalArgumentException.class, () -> Routes.requireValidNode("\udc00\ud800"));
    }

    @Test
    void allowsOrdinaryNamesDotsInsideNamesAndWellFormedPairs() {
        for (String ok : List.of("gateway", "mcp:github.create_pull_request", "a.b", "...", ".a", "a..", "caf\u00e9",
                "\ud83d\ude00")) {
            assertDoesNotThrow(() -> Routes.requireValidNode(ok), ok);
        }
    }
}
