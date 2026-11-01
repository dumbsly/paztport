// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;

class InfluenceTest {

    @Test
    void rejectsMalformed() {
        String[] bad = {
            "{}",
            "\"x\"",
            "[1]",
            "[[]]",
            "[{\"cls\":\"nope\",\"src\":\"s\",\"h\":\"x\"}]",
            "[{\"src\":\"s\",\"h\":\"x\"}]",
            "[{\"cls\":\"public\",\"src\":1,\"h\":\"x\"}]",
            "[{\"cls\":\"public\",\"src\":\"s\",\"h\":2}]",
            "[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\",\"cid\":3}]",
            "[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\",\"cid\":null}]",
            "[{\"cls\":\"private\",\"src\":\"s\",\"h\":\"x\",\"owner\":\"\"}]",
            "[{\"cls\":\"private\",\"src\":\"s\",\"h\":\"x\",\"owner\":5}]",
        };
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> Influence.parse(b), b);
        }
        assertThrows(IllegalArgumentException.class, () -> Influence.parse(null));
        assertThrows(IllegalArgumentException.class, () -> Influence.parse("[{\"cls\""));
        ObjectNode lone = JsonNodeFactory.instance.objectNode();
        lone.put("cls", "public");
        lone.put("src", "\ud800");
        lone.put("h", "x");
        String withLone = JsonNodeFactory.instance.arrayNode().add(lone).toString();
        assertThrows(IllegalArgumentException.class, () -> Influence.parse(withLone));
    }

    @Test
    void dropsUnknownFields() {
        List<InfluenceEntry> e = Influence.parse("[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\",\"extra\":1}]");
        assertEquals("{\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}", e.get(0).toJson());
    }

    @Test
    void emptyCommitsToEmptyString() {
        assertEquals("", Influence.commit(List.of()));
    }

    @Test
    void classWireNames() {
        for (InfluenceClass c : InfluenceClass.values()) {
            assertEquals(c, InfluenceClass.fromWire(c.wire()));
        }
        assertEquals(null, InfluenceClass.fromWire("other"));
    }

    @Test
    void entryRefusesWhatTheBytesCannotCarry() {
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(null, "s", "h", null, null));
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(InfluenceClass.PUBLIC, null, "h", null, null));
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(InfluenceClass.PUBLIC, "s", null, null, null));
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(InfluenceClass.PRIVATE, "s", "h", null, ""));
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(InfluenceClass.PUBLIC, "\ud800", "h", null, null));
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(InfluenceClass.PUBLIC, "s", "h", "\udc00", null));
    }
}
