// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A JSON value as Paztport reads and writes it: {@link JsonReader} builds one from bytes, and {@link JsonWriter}
 * writes one. Numbers are protocol integers only, so a value of any other number cannot be built. A string may
 * hold anything a Java string holds; the writer refuses one no reader would read.
 */
public sealed interface JsonValue {

    /** An object, its members unmodifiable and in the order they were given. */
    record Obj(Map<String, JsonValue> members) implements JsonValue {

        public Obj {
            Map<String, JsonValue> copy = new LinkedHashMap<>();
            members.forEach((name, value) -> copy.put(Objects.requireNonNull(name), Objects.requireNonNull(value)));
            members = Collections.unmodifiableMap(copy);
        }

        /** The member named, or null when there is none. */
        public JsonValue get(String name) {
            return members.get(name);
        }

        public Set<String> names() {
            return members.keySet();
        }
    }

    record Arr(List<JsonValue> items) implements JsonValue {

        public Arr {
            items = List.copyOf(items);
        }
    }

    record Str(String value) implements JsonValue {

        public Str {
            Objects.requireNonNull(value);
        }
    }

    /** A protocol integer: from 0 to 2^53 &minus; 1. */
    record Int(long value) implements JsonValue {

        public static final long MAX = (1L << 53) - 1;

        public Int {
            if (value < 0 || value > MAX) {
                throw new IllegalArgumentException("not a protocol integer: " + value);
            }
        }
    }

    record Bool(boolean value) implements JsonValue {
    }

    record Null() implements JsonValue {
    }
}
