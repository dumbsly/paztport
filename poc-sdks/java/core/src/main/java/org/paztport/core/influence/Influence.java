// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/** Parsing, normalising and committing influence entries, the same way in every SDK. */
public final class Influence {

    private static final Comparator<String> OPTIONAL_FIRST_ABSENT =
            Comparator.nullsFirst(Comparator.<String>naturalOrder());

    /** Sorts by h, cls, src, cid, then owner (absent first); String order is by UTF-16 code unit. */
    private static final Comparator<InfluenceEntry> ORDER = Comparator
            .comparing(InfluenceEntry::h)
            .thenComparing(e -> e.cls().wire())
            .thenComparing(InfluenceEntry::src)
            .thenComparing(InfluenceEntry::cid, OPTIONAL_FIRST_ABSENT)
            .thenComparing(InfluenceEntry::owner, OPTIONAL_FIRST_ABSENT);

    private static final Set<String> REQUIRED = Set.of("cls", "src", "h");
    private static final Set<String> OPTIONAL = Set.of("cid", "owner");

    private Influence() {
    }

    /**
     * Reads the wire form of an influence list from its bytes. Throws {@link IllegalArgumentException} unless
     * {@code json} is the JCS text of an array of entries, each with exactly an entry's members: a known
     * {@code cls}, {@code src} and {@code h}, and an optional {@code cid} and non-empty {@code owner}, all strings.
     */
    public static List<InfluenceEntry> parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("influence must be an array");
        }
        return fromTree(JsonReader.wireText(json));
    }

    /** {@link #parse(String)}'s schema over a value already read. */
    static List<InfluenceEntry> fromTree(JsonValue value) {
        List<InfluenceEntry> out = new ArrayList<>();
        for (JsonValue item : JsonFields.array(value)) {
            JsonValue.Obj o = JsonFields.object(item);
            JsonFields.exactly(o, REQUIRED, OPTIONAL);
            InfluenceClass cls = InfluenceClass.fromWire(JsonFields.string(o, "cls"));
            if (cls == null) {
                throw new IllegalArgumentException("member cls is not an influence class");
            }
            String cid = o.get("cid") == null ? null : JsonFields.string(o, "cid");
            String owner = o.get("owner") == null ? null : JsonFields.string(o, "owner");
            out.add(new InfluenceEntry(cls, JsonFields.string(o, "src"), JsonFields.string(o, "h"), cid, owner));
        }
        return out;
    }

    /** An opening's originals, from the tree its reader holds. */
    static List<InfluenceEntry> fromTree(JsonNode node) {
        if (node == null || !node.isArray()) {
            throw new IllegalArgumentException("influence must be an array");
        }
        List<InfluenceEntry> out = new ArrayList<>();
        for (JsonNode item : node) {
            if (!item.isObject()) {
                throw new IllegalArgumentException("influence entry must be an object");
            }
            JsonNode cls = item.get("cls");
            JsonNode src = item.get("src");
            JsonNode h = item.get("h");
            if (cls == null || !cls.isTextual() || InfluenceClass.fromWire(cls.textValue()) == null
                    || src == null || !src.isTextual() || h == null || !h.isTextual()) {
                throw new IllegalArgumentException("malformed influence entry");
            }
            String cid = optionalString(item, "cid");
            String owner = optionalString(item, "owner");
            if (owner != null && owner.isEmpty()) {
                throw new IllegalArgumentException("malformed influence owner");
            }
            for (String s : new String[] {src.textValue(), h.textValue(), cid, owner}) {
                if (s != null && (!Text.isWellFormed(s) || Text.hasNoncharacter(s))) {
                    throw new IllegalArgumentException("lone surrogate or noncharacter in influence entry");
                }
            }
            out.add(new InfluenceEntry(InfluenceClass.fromWire(cls.textValue()), src.textValue(), h.textValue(),
                    cid, owner));
        }
        return out;
    }

    private static String optionalString(JsonNode item, String name) {
        if (!item.has(name)) {
            return null;
        }
        JsonNode v = item.get(name);
        if (!v.isTextual()) {
            throw new IllegalArgumentException("malformed influence " + name);
        }
        return v.textValue();
    }

    /** Sorted copy with exact duplicates removed. An entry with an owner and one without are different. */
    public static List<InfluenceEntry> normalise(List<InfluenceEntry> entries) {
        List<InfluenceEntry> sorted = new ArrayList<>(entries);
        sorted.sort(ORDER);
        return new ArrayList<>(new LinkedHashSet<>(sorted));
    }

    /** The wire form of {@code entries}, in the order given, each as {@link InfluenceEntry#toJson()} writes it. */
    public static String toJson(List<InfluenceEntry> entries) {
        return JsonWriter.text(tree(entries));
    }

    /** The entries as a JSON value, for the writers of this SDK; not API. */
    public static JsonValue.Arr tree(List<InfluenceEntry> entries) {
        return new JsonValue.Arr(entries.stream().map(e -> (JsonValue) e.tree()).toList());
    }

    /** Empty string for no influence, otherwise b64url(SHA-256(JCS(normalised entries))). */
    public static String commit(List<InfluenceEntry> entries) {
        if (entries.isEmpty()) {
            return "";
        }
        return Base64Url.encode(Crypto.sha256(JsonWriter.wire(tree(normalise(entries)))));
    }
}
