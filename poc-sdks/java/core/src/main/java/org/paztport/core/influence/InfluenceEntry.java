// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * One piece of context that shaped an agent's output. {@code cid} and {@code owner} are null when absent; an
 * absent field is left out of the JSON rather than written as null, so the committed bytes match every other SDK.
 */
public record InfluenceEntry(InfluenceClass cls, String src, String h, String cid, String owner) {

    private static final Set<String> REQUIRED = Set.of("cls", "src", "h");
    private static final Set<String> OPTIONAL = Set.of("cid", "owner");

    /**
     * Refuses what the committed bytes could not carry: a missing field, an empty owner, a lone surrogate or a
     * noncharacter.
     */
    public InfluenceEntry {
        if (cls == null || src == null || h == null) {
            throw new IllegalArgumentException("influence entry needs cls, src and h");
        }
        if (owner != null && owner.isEmpty()) {
            throw new IllegalArgumentException("influence owner must not be empty");
        }
        for (String s : new String[] {src, h, cid, owner}) {
            if (s != null && (!Text.isWellFormed(s) || Text.hasNoncharacter(s))) {
                throw new IllegalArgumentException("lone surrogate or noncharacter in influence entry");
            }
        }
    }

    /**
     * Reads one item, its JCS text, as an entry (spec influence.md, Entries): an object with exactly a known
     * {@code cls}, a string {@code src} and {@code h}, and an optional string {@code cid} and non-empty string
     * {@code owner}.
     *
     * @throws IllegalArgumentException for text that is not the canonical text of such an object, null included
     */
    public static InfluenceEntry parse(String item) {
        if (item == null) {
            throw new IllegalArgumentException("no item text");
        }
        return fromTree(JsonReader.wireText(item));
    }

    /** {@link #parse}'s schema over a value already read. */
    static InfluenceEntry fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, REQUIRED, OPTIONAL);
        InfluenceClass cls = InfluenceClass.fromWire(JsonFields.string(o, "cls"));
        if (cls == null) {
            throw new IllegalArgumentException("member cls is not an influence class");
        }
        String cid = o.get("cid") == null ? null : JsonFields.string(o, "cid");
        String owner = o.get("owner") == null ? null : JsonFields.string(o, "owner");
        return new InfluenceEntry(cls, JsonFields.string(o, "src"), JsonFields.string(o, "h"), cid, owner);
    }

    /** The wire form: the object's JCS text, {@code {cls, src, h, cid?, owner?}} with an absent field left out. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("cls", new JsonValue.Str(cls.wire()));
        o.put("src", new JsonValue.Str(src));
        o.put("h", new JsonValue.Str(h));
        if (cid != null) {
            o.put("cid", new JsonValue.Str(cid));
        }
        if (owner != null) {
            o.put("owner", new JsonValue.Str(owner));
        }
        return new JsonValue.Obj(o);
    }

    /** What the owner-aware rule reads of this entry: its class and owner. */
    public InfluenceFact fact() {
        return new InfluenceFact(cls, owner);
    }
}
