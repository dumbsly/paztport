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
