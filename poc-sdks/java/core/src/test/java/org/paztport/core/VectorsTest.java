// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.paztport.core.policy.KeyringFile;

/** A replay hands the SDK the file's own text for each value, as the spec asks. */
class VectorsTest {

    /** The keyring written {@code 1798761600000.0} reaches the SDK as written, and is read by value. */
    @Test
    void aValueReachesTheSdkAsWritten() throws IOException {
        JsonNode v3 = Vectors.load("v3.json");
        JsonNode written = null;
        for (JsonNode c : v3.get("keyring")) {
            if (c.get("name").asText().equals("notAfter written 1798761600000.0")) {
                written = c.get("signed");
            }
        }
        String text = Vectors.json(written);
        assertTrue(text.contains("1798761600000.0"), text);
        assertFalse(written.toString().contains("1798761600000.0"), "a tree written back loses the form");
        KeyringFile ring = KeyringFile.parse(text);
        assertEquals(1_798_761_600_000L, ring.notAfter());
        assertEquals(new ObjectMapper().readTree(text), written, "the tree is the one a tree read gives");
    }

    /** Each value's text is its exact slice of the file, spacing and escapes kept; a repeated name's last wins. */
    @Test
    void eachValueIsItsOwnText() throws IOException {
        JsonNode root = Vectors.read("{ \"a\" : [ 1.0 , {\"b\":\"\\u0041\"} ], \"c\": 1, \"c\": {\"d\": 2e0} }");
        assertEquals("[ 1.0 , {\"b\":\"\\u0041\"} ]", Vectors.json(root.get("a")));
        assertEquals("{\"b\":\"\\u0041\"}", Vectors.json(root.get("a").get(1)));
        assertEquals("1.0", Vectors.json(root.get("a").get(0)));
        assertEquals("{\"d\": 2e0}", Vectors.json(root.get("c")));
        assertEquals(new ObjectMapper().readTree(Vectors.json(root)), root);
        assertThrows(IllegalArgumentException.class, () -> Vectors.json(new ObjectMapper().createObjectNode()));
    }
}
