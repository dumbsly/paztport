// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class BindingsTest {

    @Test
    void aLoneSurrogateIsRefusedNotReplacedWithAQuestionMark() {
        assertThrows(IllegalArgumentException.class, () -> Bindings.prompt("a\uD800b"));
        assertThrows(IllegalArgumentException.class, () -> Bindings.prompt("a\uDC00b"));
        assertNotEquals(Bindings.prompt("a?b"), Bindings.prompt("a\uD83D\uDE00b"));
    }

    /** v4.json, bindResponse: the response binding is the result hash and the call id, with no labels. */
    @Test
    void theResponseBindingIsTheResultHashAndTheCallId() {
        assertEquals("Ecs64bp8x8_Ehoe7svvulYX563R0KNdS25sfSg0hzXw", Bindings.response("result-hash", "call-1"));
    }

    @Test
    void aResponseBindingRefusesANewlineInTheCallIdAndALoneSurrogate() {
        assertThrows(IllegalArgumentException.class, () -> Bindings.response("h", "a\nb"));
        assertThrows(IllegalArgumentException.class, () -> Bindings.response("h\uD800", "c"));
        assertThrows(IllegalArgumentException.class, () -> Bindings.response("h", "c\uDC00"));
    }
}
