// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class NonceKeysTest {

    @Test
    void thePartsAreAJcsArray() {
        assertEquals("[\"rid-1\",\"orders\",\"payment#charge\",\"req\"]",
                NonceKeys.of("rid-1", "orders", "payment#charge", "req"));
    }

    @Test
    void partsAreEscapedAsJcsEscapesStrings() {
        assertEquals("[\"a\\\"b\",\"c|d\",\"\\n\"]", NonceKeys.of("a\"b", "c|d", "\n"));
    }

    @Test
    void aNoncharacterIsWrittenAsItself() {
        assertEquals("[\"call-\uFFFF\"]", NonceKeys.of("call-\uFFFF"));
    }

    @Test
    void aLoneSurrogateHasNoKey() {
        assertThrows(IllegalArgumentException.class, () -> NonceKeys.of("a\uD800"));
    }

    @Test
    void aNullPartHasNoKey() {
        assertThrows(IllegalArgumentException.class, () -> NonceKeys.of("a", null));
    }

    @Test
    void aDelimiterInAPartCannotJoinTwoParts() {
        assertNotEquals(NonceKeys.of("a", "b"), NonceKeys.of("a\",\"b"));
    }
}
