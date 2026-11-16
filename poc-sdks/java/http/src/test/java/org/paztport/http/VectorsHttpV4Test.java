// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays the committed {@code spec/vectors/http-v4.json} against the keys and policies in {@code v4.json}.
 * {@link VectorsHttpV4Export} holds the replay, so the builder and this test run the same code; the committed file is
 * pinned to the builder, so neither can drift from it.
 */
class VectorsHttpV4Test {

    private static JsonNode http;
    private static JsonNode core;

    @BeforeAll
    static void load() throws IOException {
        http = VectorsHttpV4Export.load("http-v4.json");
        core = VectorsHttpV4Export.load("v4.json");
    }

    @Test
    void committedMatchesBuilder() throws IOException {
        assertArrayEquals(
                VectorsHttpV4Export.loadBytes("http-v4.json"), VectorsHttpV4Export.render(VectorsHttpV4Export.build()));
    }

    @Test
    void everyCaseGivesTheRecordedAnswer() {
        VectorsHttpV4Export.assertAll(http, core);
    }
}
