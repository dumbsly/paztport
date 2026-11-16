// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.paztport.core.internal.JsonFields.array;
import static org.paztport.core.internal.JsonFields.exactly;
import static org.paztport.core.internal.JsonFields.object;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * The claims one stamp's signer attaches, and the commitment its stamp makes to them (spec wire.md, Blocks). The
 * core never reads an item; what one means is its extension's to say, so an item is held and handed out as the JCS
 * text of one JSON value.
 *
 * <p>A block copies what it is built from and hands out unmodifiable views, so its commitment cannot drift from the
 * stamp that signed it. Its maps have no inherited members, so a name such as {@code constructor} finds nothing
 * where it is not listed.
 */
public final class Block {

    private static final Pattern NAME = Pattern.compile("[a-z0-9-]{1,32}");

    /** The block that attaches nothing; its stamp's ext is "". */
    public static final Block EMPTY = new Block(new TreeMap<>(), List.of());

    /** Extension name to its items' JCS text, names in UTF-16 code unit order, as JCS writes members. */
    private final Map<String, List<String>> items;
    private final List<String> requires;
    private final String json;

    private Block(TreeMap<String, List<String>> items, List<String> requires) {
        this.items = Collections.unmodifiableMap(items);
        this.requires = requires;
        JsonValue value = toValue();
        // a block travels as an element of the array of blocks, one level deeper than alone, so the limits are
        // checked there, by the writer, and a block built here can always be written with its chain's others
        JsonWriter.text(new JsonValue.Arr(List.of(value)));
        this.json = JsonWriter.text(value);
    }

    /** Whether name is an extension name: 1 to 32 of a-z, 0-9 and '-' (spec wire.md, Blocks, Names). */
    public static boolean isExtensionName(String name) {
        return name != null && NAME.matcher(name).matches();
    }

    /**
     * A block of the given items and requirements, copied.
     *
     * @param items extension name to its items, each the JCS text of one JSON value, in the order given
     * @param requires the extensions the signer requires of the next hop; sorted here by UTF-16 code units
     * @throws IllegalArgumentException a name that is not an extension name, a name twice in requires, or an item
     *         that is not the canonical text of one value
     */
    public static Block of(Map<String, List<String>> items, Collection<String> requires) {
        TreeMap<String, List<String>> own = new TreeMap<>();
        items.forEach((name, list) -> {
            checkName(name);
            List<String> copy = new ArrayList<>();
            for (String item : list) {
                copy.add(canonical(item));
            }
            own.put(name, Collections.unmodifiableList(copy));
        });
        List<String> sorted = new ArrayList<>(requires);
        Collections.sort(sorted);
        for (int i = 0; i < sorted.size(); i++) {
            checkName(sorted.get(i));
            if (i > 0 && sorted.get(i).equals(sorted.get(i - 1))) {
                throw new IllegalArgumentException("a name twice in requires");
            }
        }
        return new Block(own, Collections.unmodifiableList(sorted));
    }

    /** The names this block names: the members of its items, in UTF-16 code unit order. */
    public Set<String> names() {
        return Collections.unmodifiableSet(new TreeSet<>(items.keySet()));
    }

    /** The items under name, each its JCS text, or null when the block does not name it. Unmodifiable. */
    public List<String> itemsUnder(String name) {
        return items.get(name);
    }

    /** Sorted, none twice. Unmodifiable. */
    public List<String> requires() {
        return requires;
    }

    /** The stamp's ext: "" for the empty block, else b64url(SHA-256(JCS(block))). */
    public String commit() {
        if (items.isEmpty() && requires.isEmpty()) {
            return "";
        }
        return Base64Url.encode(Crypto.sha256(json.getBytes(StandardCharsets.UTF_8)));
    }

    /** The block's JCS text. */
    public String toJson() {
        return json;
    }

    /**
     * Reads the JCS text of an array of blocks, by the block schema of spec wire.md, Blocks: exactly {@code items}
     * and {@code requires}, every name an extension name, every value in {@code items} an array, {@code requires}
     * strictly increasing.
     *
     * @throws IllegalArgumentException for anything else; null included
     */
    public static List<Block> parseAll(String json) {
        if (json == null) {
            throw new IllegalArgumentException("no blocks text");
        }
        List<Block> blocks = new ArrayList<>();
        for (JsonValue v : array(JsonReader.wireText(json))) {
            blocks.add(read(v));
        }
        return Collections.unmodifiableList(blocks);
    }

    /** The JCS text of an array of blocks, in the order given. */
    public static String toJson(List<Block> blocks) {
        List<JsonValue> out = new ArrayList<>();
        blocks.forEach(b -> out.add(b.toValue()));
        return JsonWriter.text(new JsonValue.Arr(out));
    }

    private static Block read(JsonValue v) {
        JsonValue.Obj o = object(v);
        exactly(o, Set.of("items", "requires"), Set.of());
        TreeMap<String, List<String>> items = new TreeMap<>();
        object(o, "items").members().forEach((name, value) -> {
            checkName(name);
            List<String> list = new ArrayList<>();
            // the reader read canonical bytes, so the writer gives back each item's own text
            array(value).forEach(item -> list.add(JsonWriter.text(item)));
            items.put(name, Collections.unmodifiableList(list));
        });
        List<String> requires = new ArrayList<>();
        for (JsonValue name : array(o, "requires")) {
            if (!(name instanceof JsonValue.Str s)) {
                throw new IllegalArgumentException("a name in requires that is not a string");
            }
            checkName(s.value());
            // strictly increasing refuses both an unsorted pair and a repeated name
            if (!requires.isEmpty() && s.value().compareTo(requires.get(requires.size() - 1)) <= 0) {
                throw new IllegalArgumentException("requires is unsorted or holds a name twice");
            }
            requires.add(s.value());
        }
        return new Block(items, Collections.unmodifiableList(requires));
    }

    private static void checkName(String name) {
        if (!isExtensionName(name)) {
            throw new IllegalArgumentException("a name that is not an extension name");
        }
    }

    /** The value one item's text reads as, refused unless the text is exactly its canonical form. */
    private static String canonical(String item) {
        Objects.requireNonNull(item, "item");
        // the wire reader refuses whitespace, member order and non-integer numbers, so a pass here is canonical
        JsonValue v = JsonReader.wireText(item);
        if (!JsonWriter.text(v).equals(item)) {
            throw new IllegalArgumentException("an item that is not the canonical text of one value");
        }
        return item;
    }

    private JsonValue toValue() {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        items.forEach((name, list) -> {
            List<JsonValue> values = new ArrayList<>();
            list.forEach(text -> values.add(JsonReader.wireText(text)));
            members.put(name, new JsonValue.Arr(values));
        });
        List<JsonValue> names = new ArrayList<>();
        requires.forEach(n -> names.add(new JsonValue.Str(n)));
        Map<String, JsonValue> block = new LinkedHashMap<>();
        block.put("items", new JsonValue.Obj(members));
        block.put("requires", new JsonValue.Arr(names));
        return new JsonValue.Obj(block);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Block b && b.json.equals(json);
    }

    @Override
    public int hashCode() {
        return json.hashCode();
    }

    @Override
    public String toString() {
        return json;
    }
}
