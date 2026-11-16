// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExtensionSettingsTest {

    @Test
    void noneActsOnNothingAndCarriesAnyName() {
        assertTrue(ExtensionSettings.NONE.actsOn().isEmpty());
        assertNull(ExtensionSettings.NONE.allowed());
        assertTrue(ExtensionSettings.NONE.carries("anything"));
    }

    @Test
    void anUnsetAllowedListCarriesAnyName() {
        assertTrue(ExtensionSettings.of(Set.of("influence"), null).carries("x"));
    }

    @Test
    void aSetAllowedListCarriesOnlyItsNames() {
        ExtensionSettings s = ExtensionSettings.of(Set.of("a"), Set.of("a", "b"));
        assertTrue(s.carries("b"));
        assertFalse(s.carries("c"));
    }

    @Test
    void aNameInActsOnOutsideAllowedIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> ExtensionSettings.of(Set.of("a"), Set.of("b")));
    }

    @Test
    void aNameThatIsNotAnExtensionNameIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> ExtensionSettings.of(Set.of("Example"), null));
        assertThrows(IllegalArgumentException.class, () -> ExtensionSettings.of(Set.of(), Set.of("a_b")));
    }

    @Test
    void aSetChangedAfterwardsDoesNotChangeTheSettings() {
        Set<String> acts = new HashSet<>(Set.of("a"));
        Set<String> allowed = new HashSet<>(Set.of("a"));
        ExtensionSettings s = ExtensionSettings.of(acts, allowed);
        acts.add("b");
        allowed.clear();
        assertEquals(Set.of("a"), s.actsOn());
        assertTrue(s.carries("a"));
    }

    @Test
    void theSetsAreUnmodifiable() {
        ExtensionSettings s = ExtensionSettings.of(Set.of("a"), Set.of("a"));
        assertThrows(UnsupportedOperationException.class, () -> s.actsOn().add("x"));
        assertThrows(UnsupportedOperationException.class, () -> s.allowed().add("x"));
    }
}
