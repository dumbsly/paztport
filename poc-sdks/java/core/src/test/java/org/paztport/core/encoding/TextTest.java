// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TextTest {

    @Test
    void hasNoncharacterFindsEachKind() {
        for (String s : new String[] {"￾", "￿", "﷐", "﷯", "a🿾", "􏿿"}) {
            assertTrue(Text.hasNoncharacter(s), s);
        }
    }

    @Test
    void hasNoncharacterPassesOtherText() {
        for (String s : new String[] {"", "plain", "café", "😀", "�", "﷏", "ﷰ", "􏿽"}) {
            assertFalse(Text.hasNoncharacter(s), s);
        }
        // a lone surrogate is not a noncharacter; isWellFormed answers for it
        assertFalse(Text.hasNoncharacter("\uD800"));
        assertFalse(Text.isWellFormed("\uD800"));
    }
}
