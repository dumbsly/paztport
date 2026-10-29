// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The one JSON entry point for the wire format. Reads fail closed: malformed or
 * unexpected JSON throws {@link IllegalArgumentException}, never a silent pass.
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            // A missing or null record component is malformed, not a default of 0 or null.
            .configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);

    private Json() {
    }

    public static byte[] write(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
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
}
