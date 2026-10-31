// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.paztport.core.Vectors;

class RequestBindingTest {

    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    @Test
    void isDeterministicForSameRequest() {
        assertEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/pay", BODY));
    }

    @Test
    void changesWhenMethodChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("GET", "/pay", BODY));
    }

    @Test
    void changesWhenPathChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/refund", BODY));
    }

    @Test
    void changesWhenBodyChanges() {
        assertNotEquals(
                RequestBinding.compute("POST", "/pay", BODY),
                RequestBinding.compute("POST", "/pay", "{\"amount\":200}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void isBase64UrlOfASha256() {
        // 32-byte digest -> 43 unpadded base64url chars.
        assertEquals(43, RequestBinding.compute("POST", "/pay", BODY).length());
    }

    @Test
    void aLoneSurrogateInTheTargetRefuses() {
        assertThrows(IllegalArgumentException.class, () -> RequestBinding.compute("GET", "/a\ud800", new byte[0]));
    }

    @Test
    void aLoneSurrogateInTheMethodRefuses() {
        assertThrows(IllegalArgumentException.class, () -> RequestBinding.compute("GE\ud800T", "/a", new byte[0]));
    }

    @Test
    void aPairedSurrogateIsBound() {
        assertEquals(43, RequestBinding.compute("GET", "/a\ud83d\ude00", new byte[0]).length());
    }

    /** The {@code http} cases of {@code spec/vectors/json.json}; core's tests replay the other bindings. */
    @TestFactory
    Stream<DynamicTest> jsonVectorsBindings() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : Vectors.load("json.json").get("bindings")) {
            if (!"http".equals(c.get("binding").textValue())) {
                continue;
            }
            JsonNode in = c.get("inputs");
            tests.add(DynamicTest.dynamicTest(c.get("name").textValue(), () -> {
                assertTrue(c.get("expected").isNull());
                assertThrows(IllegalArgumentException.class, () -> RequestBinding.compute(in.get("method").textValue(),
                        in.get("target").textValue(), HexFormat.of().parseHex(in.get("body").textValue())));
            }));
        }
        assertFalse(tests.isEmpty(), "bindings has its http cases");
        return tests.stream();
    }
}
