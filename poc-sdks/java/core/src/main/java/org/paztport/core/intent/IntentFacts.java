// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.stamp.Block;

/**
 * The facts of one intent item (spec intent.md, Facts and the item): fact names to values, each name following the
 * extension name rule and each value any JSON value the wire reader takes. A value is held as its JCS text. The
 * facts may be empty, as {@link #NONE} is, but an item is never written for none.
 */
public final class IntentFacts {

    /** No facts: what a request holds when the origin stated none. */
    public static final IntentFacts NONE = new IntentFacts(new TreeMap<>());

    private static final Set<String> ONLY_FACTS = Set.of("facts");

    private final Map<String, String> facts;

    private IntentFacts(Map<String, String> facts) {
        this.facts = Collections.unmodifiableMap(facts);
    }

    /** A builder of facts, starting with none. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds facts a name at a time, refusing at once what a reader would refuse. */
    public static final class Builder {

        private final Map<String, String> facts = new TreeMap<>();

        private Builder() {
        }

        /**
         * A fact whose value is a JSON string.
         *
         * @throws IllegalArgumentException a name that is not a fact name or is already put, or a value no reader reads
         */
        public Builder put(String name, String value) {
            if (value == null) {
                throw new IllegalArgumentException("a fact has no value; use putNull for null");
            }
            return add(name, new JsonValue.Str(value));
        }

        /**
         * A fact whose value is a protocol integer.
         *
         * @throws IllegalArgumentException a value outside 0 to 2^53 &minus; 1, or a name as {@link #put(String, String)}
         */
        public Builder put(String name, long value) {
            return add(name, new JsonValue.Int(value));
        }

        /**
         * A fact whose value is JSON null.
         *
         * @throws IllegalArgumentException a name that is not a fact name or is already put
         */
        public Builder putNull(String name) {
            return add(name, new JsonValue.Null());
        }

        /**
         * A fact whose value is the JSON text given, as the wire reader reads it.
         *
         * @throws IllegalArgumentException text the wire reader refuses, null included, or a name as
         *         {@link #put(String, String)}
         */
        public Builder putJson(String name, String json) {
            if (json == null) {
                throw new IllegalArgumentException("no value text");
            }
            return add(name, JsonReader.wireText(json));
        }

        /** The facts put so far, which may be none. */
        public IntentFacts build() {
            return new IntentFacts(new TreeMap<>(facts));
        }

        private Builder add(String name, JsonValue value) {
            checkName(name);
            if (facts.containsKey(name)) {
                throw new IllegalArgumentException("a fact named twice");
            }
            facts.put(name, JsonWriter.text(value));
            return this;
        }
    }

    private static void checkName(String name) {
        if (!Block.isExtensionName(name)) {
            throw new IllegalArgumentException("a fact name must be 1 to 32 of a-z, 0-9 and -");
        }
    }

    /**
     * Reads one item, its text, as the facts it holds (spec intent.md, Facts and the item): an object with exactly
     * one member, {@code facts}, an object of at least one member whose names follow the fact name rule.
     *
     * @throws IllegalArgumentException text that is not such an item, null included
     */
    public static IntentFacts parse(String item) {
        if (item == null) {
            throw new IllegalArgumentException("no item text");
        }
        JsonValue.Obj o = JsonFields.object(JsonReader.wireText(item));
        JsonFields.exactly(o, ONLY_FACTS, Set.of());
        JsonValue.Obj members = JsonFields.object(o.get("facts"));
        if (members.names().isEmpty()) {
            throw new IllegalArgumentException("an item with no facts");
        }
        Map<String, String> read = new TreeMap<>();
        members.members().forEach((name, value) -> {
            checkName(name);
            read.put(name, JsonWriter.text(value));
        });
        return new IntentFacts(read);
    }

    /** Whether there are no facts. */
    public boolean isEmpty() {
        return facts.isEmpty();
    }

    /** The fact names, sorted; unmodifiable. */
    public Set<String> names() {
        return facts.keySet();
    }

    /** Whether a fact has this name. */
    public boolean has(String name) {
        return facts.containsKey(name);
    }

    /** The value's JCS text; null when there is no such fact. */
    public String json(String name) {
        return facts.get(name);
    }

    /** The value when it is a JSON string; null when there is no such fact or it is another kind of value. */
    public String string(String name) {
        String text = facts.get(name);
        return text != null && JsonReader.wireText(text) instanceof JsonValue.Str s ? s.value() : null;
    }

    /** The value when it is an integer; null when there is no such fact or it is another kind of value. */
    public Long integer(String name) {
        String text = facts.get(name);
        return text != null && JsonReader.wireText(text) instanceof JsonValue.Int i ? i.value() : null;
    }

    /**
     * The item's JCS text, {@code {"facts":{...}}}.
     *
     * @throws IllegalStateException when there are no facts, since an origin with none puts no item
     */
    public String toItem() {
        if (facts.isEmpty()) {
            throw new IllegalStateException("no facts to write an item for");
        }
        Map<String, JsonValue> members = new LinkedHashMap<>();
        facts.forEach((name, text) -> members.put(name, JsonReader.wireText(text)));
        return JsonWriter.text(new JsonValue.Obj(Map.of("facts", new JsonValue.Obj(members))));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof IntentFacts f && facts.equals(f.facts);
    }

    @Override
    public int hashCode() {
        return facts.hashCode();
    }

    @Override
    public String toString() {
        return "IntentFacts" + facts;
    }
}
