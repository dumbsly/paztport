// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

/**
 * The one JSON entry point for the wire format. Reads fail closed: malformed or
 * unexpected JSON throws {@link IllegalArgumentException}, never a silent pass.
 *
 * <p>The public API takes and returns JSON text, so a user never meets the JSON library the SDK reads with. Inside,
 * text is read into a tree here, by one reader that takes exactly one JSON value and refuses trailing tokens, so a
 * header or body cannot carry a second value another parser would read differently.
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            // A missing or null record component is malformed, not a default of 0 or null.
            .configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);

    private static final ObjectMapper TREES = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    /**
     * Like {@link #TREES} but a number with a fraction or exponent keeps its written value, where the default reads it
     * as a double: {@code 9007199254740991.4} is then no longer rounded to the integer 9007199254740991.
     */
    private static final ObjectMapper EXACT_TREES = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private Json() {
    }

    public static byte[] write(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
    }

    /** {@link #write}'s JSON as text rather than UTF-8 bytes, for a value type's {@code toJson()}. */
    public static String writeText(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
    }

    public static <T> T read(byte[] bytes, Class<T> type) {
        try {
            return MAPPER.readValue(bytes, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }

    public static <T> T read(byte[] bytes, com.fasterxml.jackson.core.type.TypeReference<T> type) {
        try {
            return MAPPER.readValue(bytes, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }

    /** Exactly one JSON value read from {@code json}; null, empty or anything else throws. */
    public static JsonNode tree(String json) {
        if (json == null) {
            throw new IllegalArgumentException("no JSON");
        }
        try {
            return present(TREES.readTree(json));
        } catch (JacksonException e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }

    /**
     * Exactly one JSON value read from {@code json} as {@link #tree(String)} reads it, except that a non-integer
     * number is exact, for a caller that judges a number by its written value; null, empty or anything else throws.
     */
    public static JsonNode exactTree(String json) {
        if (json == null) {
            throw new IllegalArgumentException("no JSON");
        }
        try {
            return present(EXACT_TREES.readTree(json));
        } catch (JacksonException e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }

    /**
     * Exactly one JSON value read from a message body, in whichever Unicode encoding its first bytes show, UTF-8
     * with or without a byte order mark included; null, empty or anything else throws.
     */
    public static JsonNode tree(byte[] json) {
        if (json == null) {
            throw new IllegalArgumentException("no JSON");
        }
        try {
            return present(TREES.readTree(json));
        } catch (IOException e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }

    /** The tree as compact JSON text, members in the order they were added. */
    public static String text(JsonNode node) {
        try {
            return TREES.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
    }

    private static JsonNode present(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            throw new IllegalArgumentException("no JSON value");
        }
        return node;
    }
}
