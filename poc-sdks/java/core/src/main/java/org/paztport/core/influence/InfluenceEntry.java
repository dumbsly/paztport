// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.util.LinkedHashMap;
import java.util.Map;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * One piece of context that shaped an agent's output. {@code cid} and {@code owner} are null when absent; an
 * absent field is left out of the JSON rather than written as null, so the committed bytes match every other SDK.
 */
public record InfluenceEntry(InfluenceClass cls, String src, String h, String cid, String owner) {

    /** Refuses what the committed bytes could not carry: a missing field, an empty owner, a lone surrogate or a noncharacter. */
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

    public InfluenceFact fact() {
        return new InfluenceFact(cls, owner);
    }
}
