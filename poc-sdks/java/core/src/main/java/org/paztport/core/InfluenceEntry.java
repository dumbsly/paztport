// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * One piece of context that shaped an agent's output. {@code cid} and {@code owner} are null when absent; an
 * absent field is left out of the JSON rather than written as null, so the committed bytes match every other SDK.
 */
public record InfluenceEntry(InfluenceClass cls, String src, String h, String cid, String owner) {

    /** Refuses what the committed bytes could not carry: a missing field, an empty owner, or a lone surrogate. */
    public InfluenceEntry {
        if (cls == null || src == null || h == null) {
            throw new IllegalArgumentException("influence entry needs cls, src and h");
        }
        if (owner != null && owner.isEmpty()) {
            throw new IllegalArgumentException("influence owner must not be empty");
        }
        for (String s : new String[] {src, h, cid, owner}) {
            if (s != null && !Text.isWellFormed(s)) {
                throw new IllegalArgumentException("lone surrogate in influence entry");
            }
        }
    }

    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("cls", cls.wire());
        o.put("src", src);
        o.put("h", h);
        if (cid != null) {
            o.put("cid", cid);
        }
        if (owner != null) {
            o.put("owner", owner);
        }
        return o;
    }

    public InfluenceFact fact() {
        return new InfluenceFact(cls, owner);
    }
}
