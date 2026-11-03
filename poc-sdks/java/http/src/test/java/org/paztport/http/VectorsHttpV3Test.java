// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays the committed {@code spec/vectors/http-v3.json}, which only the Java SDK speaks, against the keys and
 * mesh policy in {@code v3.json}. {@link VectorsHttpV3Export} holds the replay, so the builder and this test run
 * the same code; the committed file is pinned to the builder, so neither can drift from it.
 */
class VectorsHttpV3Test {

    private static JsonNode http;
    private static JsonNode core;

    @BeforeAll
    static void load() throws IOException {
        http = VectorsHttpV3Export.load("http-v3.json");
        core = VectorsHttpV3Export.load("v3.json");
    }

    @Test
    void committedMatchesBuilder() throws IOException {
        assertArrayEquals(
                VectorsHttpV3Export.loadBytes("http-v3.json"), VectorsHttpV3Export.render(VectorsHttpV3Export.build()));
    }

    @Test
    void everyCaseGivesTheRecordedAnswer() {
        VectorsHttpV3Export.assertAll(http, core);
    }
}
