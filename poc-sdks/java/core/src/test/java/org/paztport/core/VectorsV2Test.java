// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Replays the committed v2 vectors in {@code spec/vectors/v2.json}, one test method per section. */
class VectorsV2Test {

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v2.json");
    }

    @Test
    void commitInfluence() {
        JsonNode c = vectors.get("commitInfluence");
        assertEquals(c.get("expected").asText(), Influence.commit(Influence.parse(c.get("entries"))));
    }

    @Test
    void signingBytesV2() {
        JsonNode c = vectors.get("signingBytesV2");
        JsonNode s = c.get("stamp");
        StampV2 stamp = new StampV2(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(),
                s.get("ts").asLong(), s.get("sess").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), "");
        assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp.signingBytes()));
    }

    @Test
    void bindPrompt() {
        JsonNode c = vectors.get("bindPrompt");
        assertEquals(c.get("expected").asText(), Bindings.prompt(c.get("prompt").asText()));
    }
}
