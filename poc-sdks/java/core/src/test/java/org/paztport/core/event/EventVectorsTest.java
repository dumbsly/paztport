// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.Vectors;
import org.paztport.core.internal.JsonWriter;

/**
 * Replays the committed {@code spec/vectors/events.json}, read from the file's own text. {@link EventVectorsExport}
 * holds the replay, so the builder and this test run the same code, and the committed file is pinned to the
 * builder, so neither can drift from the other.
 */
class EventVectorsTest {

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("events.json");
    }

    @Test
    void committedMatchesBuilder() throws IOException {
        assertArrayEquals(EventVectorsExport.loadBytes("events.json"),
                EventVectorsExport.render(EventVectorsExport.build()));
    }

    @Test
    void everyCaseGivesTheRecordedAnswer() {
        EventVectorsExport.assertAll(vectors);
    }

    /** The text each envelope case signs is its event's JCS text, the only bytes a responder reads as that event. */
    @Test
    void everyEnvelopeCaseSignsItsEventsJcsText() {
        for (JsonNode c : vectors.get("envelope")) {
            assertEquals(JsonWriter.text(Vectors.value(c.get("event"))), c.get("eventJson").asText(),
                    c.get("name").asText());
        }
    }

    /** The file is the spec's evidence for every refusal, so each one has a case, and so does acceptance. */
    @Test
    void everyRefusalAndAcceptanceHasACase() {
        Set<String> seen = new HashSet<>();
        for (JsonNode c : vectors.get("verify")) {
            JsonNode refusal = c.get("expected").get("refusal");
            seen.add(refusal.isNull() ? "accepted" : refusal.asText());
        }
        assertTrue(seen.contains("accepted"), "an accepted case");
        for (EventVerifier.Refusal r : EventVerifier.Refusal.values()) {
            assertTrue(seen.contains(r.name()), "a case refused " + r);
        }
    }
}
