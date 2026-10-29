// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;

/**
 * What a response says about its own content: a class, a content id the caller can later cite, and (for private
 * content) whose it is. Labels travel beside a response and are committed by its binding, so a caller can trust
 * them exactly as far as it trusts the responder's stamp. {@code owner} is null when absent and is then left out of
 * the JSON, never written as null, so the bound bytes match every other SDK.
 */
public record ContentLabel(InfluenceClass cls, String cid, String owner) {

    /** Refuses a missing class or cid, an empty owner, or a lone surrogate, none of which the binding could carry. */
    public ContentLabel {
        if (cls == null || cid == null) {
            throw new IllegalArgumentException("content label needs cls and cid");
        }
        if (owner != null && owner.isEmpty()) {
            throw new IllegalArgumentException("content label owner must not be empty");
        }
        if (!Text.isWellFormed(cid) || (owner != null && !Text.isWellFormed(owner))) {
            throw new IllegalArgumentException("lone surrogate in content label");
        }
    }

    /** A label for new content, with a random 16-byte content id. */
    public static ContentLabel fresh(InfluenceClass cls, String owner) {
        return new ContentLabel(cls, Base64Url.encode(Crypto.randomBytes(16)), owner);
    }

    /** Throws {@link IllegalArgumentException} unless the node is an array of well-formed labels; unknown fields are dropped. */
    public static List<ContentLabel> parseAll(JsonNode node) {
        if (node == null || !node.isArray()) {
            throw new IllegalArgumentException("labels must be an array");
        }
        List<ContentLabel> out = new ArrayList<>();
        for (JsonNode item : node) {
            if (!item.isObject()) {
                throw new IllegalArgumentException("label must be an object");
            }
            JsonNode cls = item.get("cls");
            JsonNode cid = item.get("cid");
            JsonNode owner = item.get("owner");
            if (cls == null || !cls.isTextual() || InfluenceClass.fromWire(cls.textValue()) == null
                    || cid == null || !cid.isTextual()) {
                throw new IllegalArgumentException("malformed label");
            }
            if (owner != null && !owner.isTextual()) {
                throw new IllegalArgumentException("malformed label owner");
            }
            out.add(new ContentLabel(InfluenceClass.fromWire(cls.textValue()), cid.textValue(),
                    owner == null ? null : owner.textValue()));
        }
        return out;
    }

    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("cls", cls.wire());
        o.put("cid", cid);
        if (owner != null) {
            o.put("owner", owner);
        }
        return o;
    }

    /** The influence entry a receiver records for content carrying this label. */
    public InfluenceEntry toEntry(String src, String h) {
        return new InfluenceEntry(cls, src, h, cid, owner);
    }
}
