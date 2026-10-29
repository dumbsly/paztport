// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

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
}
