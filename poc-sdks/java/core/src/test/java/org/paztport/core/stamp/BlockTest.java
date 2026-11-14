// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BlockTest {

    @Test
    void theEmptyBlockCommitsToTheEmptyString() {
        assertEquals("", Block.EMPTY.commit());
        assertEquals("{\"items\":{},\"requires\":[]}", Block.EMPTY.toJson());
        assertEquals("", Block.of(Map.of(), List.of()).commit());
    }

    @Test
    void aBlockThatNamesAnExtensionWithNothingIsNotTheEmptyBlock() {
        Block b = Block.of(Map.of("example", List.of()), List.of());
        assertNotEquals("", b.commit());
        assertEquals(List.of(), b.itemsUnder("example"));
        assertNull(b.itemsUnder("influence"));
        assertNull(Block.of(Map.of(), List.of("example")).itemsUnder("example"),
                "a name only in requires is not named");
    }

    @Test
    void aNameNoInheritedMemberCanAnswer() {
        assertNull(Block.EMPTY.itemsUnder("constructor"));
        assertNull(Block.EMPTY.itemsUnder("toString"));
    }

    @Test
    void requiresIsSortedAndANameTwiceIsRefused() {
        assertEquals(List.of("a", "b"), Block.of(Map.of(), List.of("b", "a")).requires());
        assertThrows(IllegalArgumentException.class, () -> Block.of(Map.of(), List.of("a", "a")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Example", "a_b", "abcdefghijklmnopqrstuvwxyz0123456"})
    void aNameThatIsNotAnExtensionNameIsRefused(String name) {
        assertThrows(IllegalArgumentException.class, () -> Block.of(Map.of(name, List.of()), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Block.of(Map.of(), List.of(name)));
    }

    @ParameterizedTest
    @ValueSource(strings = {" 1", "{\"b\":1,\"a\":2}", "1.0", "[1,]", "1 2", ""})
    void anItemThatIsNotCanonicalTextIsRefused(String item) {
        assertThrows(IllegalArgumentException.class, () -> Block.of(Map.of("example", List.of(item)), List.of()));
    }

    @Test
    void aBlockDoesNotChangeWithTheListsItWasBuiltFrom() {
        List<String> items = new ArrayList<>(List.of("1"));
        Block b = Block.of(Map.of("example", items), List.of());
        String before = b.commit();
        items.add("2");
        assertEquals(before, b.commit());
        assertEquals(List.of("1"), b.itemsUnder("example"));
        assertThrows(UnsupportedOperationException.class, () -> b.itemsUnder("example").add("3"));
        assertThrows(UnsupportedOperationException.class, () -> b.requires().add("x"));
        assertThrows(UnsupportedOperationException.class, () -> b.names().add("x"));
    }

    @Test
    void namesAreInCodeUnitOrderAndItemsKeepTheirOrder() {
        Block b = Block.of(Map.of("b", List.of("2", "1"), "a", List.of()), List.of());
        assertEquals(List.of("a", "b"), List.copyOf(b.names()));
        assertEquals(List.of("2", "1"), b.itemsUnder("b"));
        assertEquals("{\"items\":{\"a\":[],\"b\":[2,1]},\"requires\":[]}", b.toJson());
    }

    @Test
    void whatIsWrittenReadsBack() {
        List<Block> blocks = List.of(Block.EMPTY,
                Block.of(Map.of("example", List.of("null", "true", "false", "0", "\"é\"", "[]", "{}",
                        "[1,[2]]", "{\"a\":{\"b\":null}}")), List.of("example", "other")));
        assertEquals(blocks, Block.parseAll(Block.toJson(blocks)));
        assertEquals("[]", Block.toJson(List.of()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "{}", "[{\"items\":{}}]", "[{\"items\":{},\"requires\":[],\"x\":1}]",
        "[{\"items\":{\"example\":{}},\"requires\":[]}]", "[{\"items\":{},\"requires\":[\"b\",\"a\"]}]",
        "[{\"items\":{},\"requires\":[\"a\",\"a\"]}]", "[{\"items\":{},\"requires\":[1]}]", "[ ]"})
    void whatIsNotAnArrayOfBlocksDoesNotRead(String json) {
        assertThrows(IllegalArgumentException.class, () -> Block.parseAll(json));
    }

    @Test
    void nullDoesNotRead() {
        assertThrows(IllegalArgumentException.class, () -> Block.parseAll(null));
    }
}
