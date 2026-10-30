// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JcsWriter;
import org.paztport.core.internal.Json;

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

    private Influence() {
    }

    /**
     * Reads the wire form of an influence list. Throws {@link IllegalArgumentException} unless {@code json} is an
     * array of well-formed entries; unknown fields are dropped.
     */
    public static List<InfluenceEntry> parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("influence must be an array");
        }
        return fromTree(Json.tree(json));
    }

    /** {@link #parse(String)} over a tree already read, as an opening's originals are. */
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
                if (s != null && !Text.isWellFormed(s)) {
                    throw new IllegalArgumentException("lone surrogate in influence entry");
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
        return Json.text(tree(entries));
    }

    static ArrayNode tree(List<InfluenceEntry> entries) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        for (InfluenceEntry e : entries) {
            a.add(e.tree());
        }
        return a;
    }

    /** Empty string for no influence, otherwise b64url(SHA-256(JCS(normalised entries))). */
    public static String commit(List<InfluenceEntry> entries) {
        if (entries.isEmpty()) {
            return "";
        }
        return Base64Url.encode(Crypto.sha256(JcsWriter.bytes(tree(normalise(entries)))));
    }
}
