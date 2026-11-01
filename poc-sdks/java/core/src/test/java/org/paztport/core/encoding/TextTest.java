// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TextTest {

    @Test
    void hasNoncharacterFindsEachKind() {
        for (String s : new String[] {"\uFFFE", "\uFFFF", "\uFDD0", "\uFDEF", "a\uD83F\uDFFE", "\uDBFF\uDFFF"}) {
            assertTrue(Text.hasNoncharacter(s), s);
        }
    }

    @Test
    void hasNoncharacterPassesOtherText() {
        for (String s : new String[] {"", "plain", "caf\u00E9", "\uD83D\uDE00", "\uFFFD", "\uFDCF", "\uFDF0",
                "\uDBFF\uDFFD"}) {
            assertFalse(Text.hasNoncharacter(s), s);
        }
        // a lone surrogate is not a noncharacter; isWellFormed answers for it
        assertFalse(Text.hasNoncharacter("\uD800"));
        assertFalse(Text.isWellFormed("\uD800"));
    }
}
