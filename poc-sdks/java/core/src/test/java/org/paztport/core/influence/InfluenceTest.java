// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
            "[{\"cls\":\"nope\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":1}]",
            "[{\"cls\":\"public\",\"h\":2,\"src\":\"s\"}]",
            "[{\"cid\":3,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cid\":null,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cls\":\"private\",\"h\":\"x\",\"owner\":\"\",\"src\":\"s\"}]",
            "[{\"cls\":\"private\",\"h\":\"x\",\"owner\":5,\"src\":\"s\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ud800\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ufdd0\"}]",
        };
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> Influence.parse(b), b);
        }
        assertThrows(IllegalArgumentException.class, () -> Influence.parse(null));
        assertThrows(IllegalArgumentException.class, () -> Influence.parse("[{\"cls\""));
        String good = "[{\"cid\":\"c\",\"cls\":\"private\",\"h\":\"x\",\"owner\":\"o\",\"src\":\"s\"}]";
        assertEquals(good, Influence.toJson(Influence.parse(good)));
    }

    @Test
    void anEntryWithAnExtraMemberIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[{\"cls\":\"public\",\"extra\":1,\"h\":\"x\",\"src\":\"s\"}]"));
    }

    @Test
    void aListInWireMemberOrderIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\"}]"));
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[ {\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]"));
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
