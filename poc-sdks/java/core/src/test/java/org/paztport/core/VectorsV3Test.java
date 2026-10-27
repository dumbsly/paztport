// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays the committed v3 vectors in {@code spec/vectors/v3.json}, the file the TypeScript SDK also reads. One
 * test method per section, so a failure names the section.
 */
class VectorsV3Test {

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v3.json");
    }

    @Test
    void influence() {
        for (JsonNode c : vectors.get("influence")) {
            String name = c.get("name").asText();
            List<InfluenceEntry> normalised = Influence.normalise(Influence.parse(c.get("entries")));
            assertEquals(c.get("normalized"), Influence.toJson(normalised), name);
            assertEquals(c.get("commitment").asText(), Influence.commit(Influence.parse(c.get("entries"))), name);
        }
    }

    @Test
    void rule() {
        for (JsonNode c : vectors.get("rule")) {
            List<InfluenceFact> facts = new ArrayList<>();
            for (JsonNode f : c.get("influence")) {
                facts.add(new InfluenceFact(
                        InfluenceClass.fromWire(f.get("cls").asText()),
                        f.has("owner") ? f.get("owner").asText() : null));
            }
            JsonNode dest = c.get("destinationOwner");
            String owner = dest == null || dest.isNull() ? null : dest.asText();
            assertEquals(c.get("refused").asBoolean(), InfluenceRule.publicWriteRefused(facts, owner),
                    c.get("name").asText());
        }
    }
}
