// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
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
     * Reads the wire form of a label list: the JCS text of an array of labels, each with exactly {@code cls} and
     * {@code cid} and, for private content, {@code owner}. Throws {@link IllegalArgumentException} for text that is
     * not that, or for a label that is not well formed.
     */
    public static List<ContentLabel> parseAll(String json) {
        if (json == null) {
            throw new IllegalArgumentException("labels must be an array");
        }
        List<ContentLabel> out = new ArrayList<>();
        for (JsonValue item : JsonFields.array(JsonReader.wireText(json))) {
            JsonValue.Obj label = JsonFields.object(item);
            JsonFields.exactly(label, Set.of("cls", "cid"), Set.of("owner"));
            InfluenceClass cls = InfluenceClass.fromWire(JsonFields.string(label, "cls"));
            if (cls == null) {
                throw new IllegalArgumentException("malformed label");
            }
            out.add(new ContentLabel(cls, JsonFields.string(label, "cid"),
                    label.get("owner") == null ? null : JsonFields.string(label, "owner")));
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
