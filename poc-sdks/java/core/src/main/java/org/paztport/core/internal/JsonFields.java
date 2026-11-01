// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The schema step of reading an object (the spec's JSON reading, step 4), for a value {@link JsonReader} has read:
 * the value is an object, it has exactly the members its section defines, and each is of its type. Each refusal is
 * an {@link IllegalArgumentException} that names the member the schema defines, never a name or value the input
 * chose.
 */
public final class JsonFields {

    private JsonFields() {
    }

    /** {@code v} as an object; anything else is refused. */
    public static JsonValue.Obj object(JsonValue v) {
        if (v instanceof JsonValue.Obj o) {
            return o;
        }
        throw new IllegalArgumentException("not an object");
    }

    /** Refuses {@code o} unless it has every member in {@code required} and none outside it and {@code optional}. */
    public static void exactly(JsonValue.Obj o, Set<String> required, Set<String> optional) {
        for (String name : required) {
            if (o.get(name) == null) {
                throw new IllegalArgumentException("no member " + name);
            }
        }
        for (String name : o.names()) {
            if (!required.contains(name) && !optional.contains(name)) {
                throw new IllegalArgumentException("a member the object does not define");
            }
        }
    }

    /** The string member {@code name}; absent or of another type is refused. */
    public static String string(JsonValue.Obj o, String name) {
        if (o.get(name) instanceof JsonValue.Str s) {
            return s.value();
        }
        throw new IllegalArgumentException("member " + name + " is not a string");
    }

    /** The integer member {@code name}, a protocol integer; absent or of another type is refused. */
    public static long integer(JsonValue.Obj o, String name) {
        if (o.get(name) instanceof JsonValue.Int i) {
            return i.value();
        }
        throw new IllegalArgumentException("member " + name + " is not an integer");
    }

    /** The boolean member {@code name}; absent or of another type is refused. */
    public static boolean bool(JsonValue.Obj o, String name) {
        if (o.get(name) instanceof JsonValue.Bool b) {
            return b.value();
        }
        throw new IllegalArgumentException("member " + name + " is not a boolean");
    }

    /**
     * A map by definition, such as a keyring's {@code services}: an object whose every value is a string, in the
     * order read. Its names are data, so the caller checks them by its section's rules.
     */
    public static Map<String, String> stringMap(JsonValue v) {
        Map<String, String> out = new LinkedHashMap<>();
        object(v).members().forEach((name, value) -> {
            if (!(value instanceof JsonValue.Str s)) {
                throw new IllegalArgumentException("a map value that is not a string");
            }
            out.put(name, s.value());
        });
        return Collections.unmodifiableMap(out);
    }
}
