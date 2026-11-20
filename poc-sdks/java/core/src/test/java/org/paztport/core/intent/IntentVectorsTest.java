// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.Vectors;

/**
 * Replays the committed {@code spec/vectors/intent.json}, read from the file's own text. {@link IntentVectorsExport}
 * holds the replay, so the builder and this test run the same code, and the committed file is pinned to the builder.
 */
class IntentVectorsTest {

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("intent.json");
    }

    @Test
    void committedMatchesBuilder() throws IOException {
        assertArrayEquals(IntentVectorsExport.loadBytes("intent.json"),
                IntentVectorsExport.render(IntentVectorsExport.build()));
    }

    @Test
    void everyCaseGivesTheRecordedAnswer() {
        IntentVectorsExport.assertAll(vectors);
    }

    /** The file is the spec's evidence for every answer, so each one has a case, and so has an item that does not read. */
    @Test
    void everyRefusalHasACase() {
        Set<String> seen = new HashSet<>();
        vectors.get("requests").forEach(c -> seen.add(c.get("require").asText()));
        assertTrue(seen.containsAll(Set.of("OK", "INTENT_MISSING", "INTENT_MISMATCH")), seen.toString());
        boolean unread = false;
        for (JsonNode c : vectors.get("items")) {
            unread |= c.get("facts").isNull();
        }
        assertTrue(unread, "an item that does not read");
    }
}
