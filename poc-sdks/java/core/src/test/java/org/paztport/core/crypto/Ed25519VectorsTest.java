// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.paztport.core.Vectors;
import org.paztport.core.encoding.Base64Url;

/**
 * Replays the committed {@code spec/vectors/ed25519.json}: crafted keys and signatures the libraries disagree on,
 * with answers the file's generator worked out by its own RFC 8032 arithmetic. The three SDKs replay the same file, so
 * they refuse the same bytes.
 */
class Ed25519VectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("ed25519.json");
    }

    @Test
    void hasTwentyEightCases() {
        assertEquals(28, vectors.get("cases").size());
    }

    @Test
    void constantsAreTheVectors() {
        JsonNode file = vectors.get("smallOrderY");
        assertEquals(file.size(), Ed25519Strict.SMALL_ORDER_Y.length);
        for (int i = 0; i < file.size(); i++) {
            // the file writes each y as its 32 little-endian bytes, the order the check holds them in
            byte[] expected = HEX.parseHex(file.get(i).textValue());
            assertEquals(HEX.formatHex(expected), HEX.formatHex(Ed25519Strict.SMALL_ORDER_Y[i]), "y #" + i);
        }
    }

    @TestFactory
    Stream<DynamicTest> everyCaseGivesTheRecordedAnswer() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : vectors.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("name").textValue(),
                    () -> assertEquals(c.get("valid").booleanValue(), verifies(c))));
        }
        return tests.stream();
    }

    /**
     * A library that answers otherwise after rules 1 to 4 pass (one that multiplies by the cofactor, say) is one the
     * checks in front cannot correct: the rule would then depend on the library build.
     */
    @Test
    void theLibraryAloneDisagreesOnlyWhereTheCheckIsNeeded() {
        List<String> wrong = new ArrayList<>();
        for (JsonNode c : vectors.get("cases")) {
            if (bareLibrary(c) != c.get("valid").booleanValue()) {
                wrong.add(c.get("name").textValue());
                assertFalse(rulesOneToFour(c), c.get("name").textValue());
            }
        }
        System.out.println("JDK Signature alone answers otherwise on: " + wrong);
    }

    /** The SDK's verify; a key the JDK refuses at decode time is a key that does not verify. */
    private static boolean verifies(JsonNode c) {
        PublicKey key;
        try {
            key = Crypto.decodePublicKey(Base64Url.decode(c.get("publicKey").textValue()));
        } catch (IllegalArgumentException e) {
            return false;
        }
        return Crypto.verify(key, Base64Url.decode(c.get("message").textValue()),
                Base64Url.decode(c.get("signature").textValue()));
    }

    /** The JDK's Signature with nothing in front of it; a key or signature it refuses counts as not valid. */
    private static boolean bareLibrary(JsonNode c) {
        try {
            PublicKey key = Crypto.decodePublicKey(Base64Url.decode(c.get("publicKey").textValue()));
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(Base64Url.decode(c.get("message").textValue()));
            return s.verify(Base64Url.decode(c.get("signature").textValue()));
        } catch (java.security.GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean rulesOneToFour(JsonNode c) {
        byte[] spki = Base64Url.decode(c.get("publicKey").textValue());
        byte[] prefix = HEX.parseHex("302a300506032b6570032100");
        if (spki.length != 44 || !Arrays.equals(Arrays.copyOf(spki, 12), prefix)) {
            return false;
        }
        return Ed25519Strict.encodings(Arrays.copyOfRange(spki, 12, 44),
                Base64Url.decode(c.get("signature").textValue()));
    }
}
