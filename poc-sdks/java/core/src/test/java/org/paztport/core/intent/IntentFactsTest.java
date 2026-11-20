// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class IntentFactsTest {

    @Test
    void buildsTheCanonicalItem() {
        IntentFacts f = IntentFacts.builder().put("order", "123").put("amount", 100).put("customer", "alice").build();
        assertEquals("{\"facts\":{\"amount\":100,\"customer\":\"alice\",\"order\":\"123\"}}", f.toItem());
        assertEquals(f.toItem(), IntentFacts.parse(f.toItem()).toItem());
    }

    @Test
    void readsEachKindOfValue() {
        IntentFacts f = IntentFacts.parse("{\"facts\":{\"a\":\"x\",\"b\":7,\"c\":null,\"d\":{\"k\":[1]}}}");
        assertEquals("x", f.string("a"));
        assertNull(f.integer("a"));
        assertEquals(7L, f.integer("b"));
        assertNull(f.string("b"));
        assertTrue(f.has("c"));
        assertEquals("null", f.json("c"));
        assertEquals("{\"k\":[1]}", f.json("d"));
        assertFalse(f.has("e"));
        assertNull(f.json("e"));
    }

    @Test
    void namesAreSortedAndNoneIsEmpty() {
        assertEquals(java.util.List.of("a", "b"),
                java.util.List.copyOf(IntentFacts.builder().put("b", 1).putNull("a").build().names()));
        assertTrue(IntentFacts.NONE.isEmpty());
        assertTrue(IntentFacts.NONE.names().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"facts\":{}}", "{}", "[]", "{\"facts\":[]}", "{\"facts\":{\"a\":1},\"more\":1}",
        "{\"facts\":{\"A\":1}}", "{\"facts\":{\"\":1}}", "{\"facts\":{\"a\":1.5}}", "{\"facts\":{\"a\":1,\"a\":2}}",
        "{\"facts\":{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":1}}", "not json"})
    void refusesAnItemThatDoesNotRead(String item) {
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.parse(item));
    }

    @Test
    void refusesNullText() {
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.parse(null));
    }

    @Test
    void theBuilderRefusesWhatAReaderWould() {
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("A", "x"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("", "x"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("a".repeat(33), "x"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().putNull("a b"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("a", 1).put("a", 2));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("a", "x").putNull("a"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().putJson("a", "1.5"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().putJson("a", "not json"));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("a", -1));
        assertThrows(IllegalArgumentException.class, () -> IntentFacts.builder().put("a", 1L << 53));
        assertThrows(IllegalStateException.class, IntentFacts.NONE::toItem);
        assertThrows(IllegalStateException.class, () -> IntentFacts.builder().build().toItem());
    }

    @Test
    void putJsonKeepsTheValueAsItsCanonicalText() {
        IntentFacts f = IntentFacts.builder().putJson("a", "{\"k\":[1,true]}").build();
        assertEquals("{\"k\":[1,true]}", f.json("a"));
        assertEquals("{\"facts\":{\"a\":{\"k\":[1,true]}}}", f.toItem());
    }
}
