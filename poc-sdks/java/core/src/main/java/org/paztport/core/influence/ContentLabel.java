// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.Json;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * What a response says about its own content: a class, a content id the caller can later cite, and (for private
 * content) whose it is. Labels travel beside a response and are committed by its binding, so a caller can trust
 * them exactly as far as it trusts the responder's stamp. {@code owner} is null when absent and is then left out of
 * the JSON, never written as null, so the bound bytes match every other SDK.
 */
public record ContentLabel(InfluenceClass cls, String cid, String owner) {

    /**
     * Refuses a missing class or cid, an empty owner, a lone surrogate or a noncharacter, none of which the binding
     * could carry.
     */
    public ContentLabel {
        if (cls == null || cid == null) {
            throw new IllegalArgumentException("content label needs cls and cid");
        }
        if (owner != null && owner.isEmpty()) {
            throw new IllegalArgumentException("content label owner must not be empty");
        }
        if (!Text.isWellFormed(cid) || Text.hasNoncharacter(cid)
                || (owner != null && (!Text.isWellFormed(owner) || Text.hasNoncharacter(owner)))) {
            throw new IllegalArgumentException("lone surrogate or noncharacter in content label");
        }
    }

    /** A label for new content, with a random 16-byte content id. */
    public static ContentLabel fresh(InfluenceClass cls, String owner) {
        return new ContentLabel(cls, Base64Url.encode(Crypto.randomBytes(16)), owner);
    }

    /**
     * Reads the wire form of a label list. Throws {@link IllegalArgumentException} unless {@code json} is an array
     * of well-formed labels; unknown fields are dropped.
     */
    public static List<ContentLabel> parseAll(String json) {
        if (json == null) {
            throw new IllegalArgumentException("labels must be an array");
        }
        JsonNode node = Json.tree(json);
        if (!node.isArray()) {
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

    /** The wire form of {@code labels}, in the order given, each as {@link #toJson()} writes it. */
    public static String toJson(List<ContentLabel> labels) {
        return JsonWriter.text(tree(labels));
    }

    /** The labels as a JSON value, for the writers of this SDK; not API. */
    public static JsonValue.Arr tree(List<ContentLabel> labels) {
        return new JsonValue.Arr(labels.stream().map(l -> (JsonValue) l.tree()).toList());
    }

    /** The wire form: the object's JCS text, {@code {cls, cid, owner?}} with an absent owner left out. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    private JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("cls", new JsonValue.Str(cls.wire()));
        o.put("cid", new JsonValue.Str(cid));
        if (owner != null) {
            o.put("owner", new JsonValue.Str(owner));
        }
        return new JsonValue.Obj(o);
    }

    /** The influence entry a receiver records for content carrying this label. */
    public InfluenceEntry toEntry(String src, String h) {
        return new InfluenceEntry(cls, src, h, cid, owner);
    }
}
