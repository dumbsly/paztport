// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
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

    /**
     * Every verify case without its own {@code keyrings}, given the file's keyring as the optional per-case
     * {@code keyrings}, whole or split one service to a keyring, gives the answer it gives under the file's keyring:
     * the replay reads the keyrings a case may carry.
     */
    @Test
    void theOptionalKeyringsGiveTheAnswersOfTheFileKeyring() {
        ObjectNode names = JsonNodeFactory.instance.objectNode();
        vectors.get("responder").get("keyring").properties().forEach(e -> vectors.get("keys").properties().forEach(
                k -> {
                    if (k.getValue().get("pub").equals(e.getValue())) {
                        names.put(e.getKey(), k.getKey());
                    }
                }));
        assertEquals(vectors.get("responder").get("keyring").size(), names.size(), "a key name for each service");
        ArrayNode whole = JsonNodeFactory.instance.arrayNode().add(names);
        ArrayNode split = JsonNodeFactory.instance.arrayNode();
        names.properties().forEach(e -> split.addObject().set(e.getKey(), e.getValue()));
        JsonNode accepted = null;
        for (JsonNode c : vectors.get("verify")) {
            if (c.has("keyrings")) {
                continue;
            }
            EventVerifier.Outcome want = EventVectorsExport.run(vectors, c);
            for (ArrayNode keyrings : List.of(whole, split)) {
                ObjectNode with = c.deepCopy();
                with.set("keyrings", keyrings);
                assertEquals(want, EventVectorsExport.run(vectors, with), c.get("name").asText());
            }
            accepted = c.get("name").asText().equals("accepted") ? c : accepted;
        }
        // And the case's keyrings are what is used: without the signer's, an event it signed has no key.
        ObjectNode keyless = accepted.deepCopy();
        keyless.set("keyrings", JsonNodeFactory.instance.arrayNode().add(JsonNodeFactory.instance.objectNode()
                .put("search", "search")));
        assertEquals(EventVerifier.Refusal.UNKNOWN_SIGNER, EventVectorsExport.run(vectors, keyless).refusal());
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
