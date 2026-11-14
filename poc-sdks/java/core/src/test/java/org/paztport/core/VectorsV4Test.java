// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.stamp.Block;

/** Replays {@code spec/vectors/v4.json}. */
class VectorsV4Test {

    private static JsonNode v4;

    @BeforeAll
    static void load() throws IOException {
        v4 = Vectors.load("v4.json");
    }

    @Test
    void blocksRead() {
        int read = 0;
        int refused = 0;
        for (JsonNode c : v4.get("blocks").get("read")) {
            String token = Vectors.tokenText(c.get("token"));
            String name = c.get("name").textValue();
            if (c.get("expected").textValue().equals("OK")) {
                read++;
                List<Block> blocks = Block.parseAll(token);
                assertEquals(Vectors.text(c.get("blocks")), Block.toJson(blocks), name);
            } else {
                refused++;
                assertThrows(IllegalArgumentException.class, () -> Block.parseAll(token), name);
            }
        }
        assertTrue(read > 0 && refused > 0, "the section holds both outcomes");
    }

    @Test
    void blocksCommit() {
        int cases = 0;
        for (JsonNode c : v4.get("blocks").get("commit")) {
            cases++;
            String name = c.get("name").textValue();
            List<Block> one = Block.parseAll("[" + Vectors.text(c.get("block")) + "]");
            assertEquals(c.get("jcs").textValue(), one.get(0).toJson(), name);
            assertEquals(c.get("ext").textValue(), one.get(0).commit(), name);
        }
        assertTrue(cases > 0);
    }
}
