// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;

class InfluenceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String s) throws Exception {
        return MAPPER.readTree(s);
    }

    @Test
    void rejectsMalformed() throws Exception {
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
            JsonNode n = json(b);
            assertThrows(IllegalArgumentException.class, () -> Influence.parse(n), b);
        }
        ObjectNode lone = JsonNodeFactory.instance.objectNode();
        lone.put("cls", "public");
        lone.put("src", "\ud800");
        lone.put("h", "x");
        assertThrows(IllegalArgumentException.class, () -> Influence.parse(JsonNodeFactory.instance.arrayNode().add(lone)));
    }

    @Test
    void dropsUnknownFields() throws Exception {
        List<InfluenceEntry> e = Influence.parse(json("[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\",\"extra\":1}]"));
        assertEquals(json("{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\"}"), e.get(0).toJson());
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
}
