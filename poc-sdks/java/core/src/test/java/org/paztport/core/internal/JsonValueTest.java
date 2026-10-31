// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonValueTest {

    @Test
    void anIntOutsideTheRangeCannotBeBuilt() {
        assertThrows(IllegalArgumentException.class, () -> new JsonValue.Int(-1));
        assertThrows(IllegalArgumentException.class, () -> new JsonValue.Int(1L << 53));
        assertEquals(0, new JsonValue.Int(0).value());
        assertEquals((1L << 53) - 1, new JsonValue.Int((1L << 53) - 1).value());
    }

    @Test
    void anObjectKeepsItsMembersInSourceOrderAndCannotChange() {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        members.put("b", new JsonValue.Int(1));
        members.put("a", new JsonValue.Null());
        JsonValue.Obj o = new JsonValue.Obj(members);
        members.put("c", new JsonValue.Bool(true));

        assertEquals(List.of("b", "a"), List.copyOf(o.names()));
        assertEquals(new JsonValue.Int(1), o.get("b"));
        assertNull(o.get("c"));
        assertThrows(UnsupportedOperationException.class, () -> o.members().put("c", new JsonValue.Null()));
    }
}
