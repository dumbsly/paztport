// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * Finds and loads a committed vector file from {@code spec/vectors/} by walking up from the working directory,
 * so a test does not depend on which module or directory Maven was started from. Shared with the http module's
 * tests through core's test jar.
 *
 * <p>A replay hands the SDK each value's own text from the file, not the tree written back out: the spec asks for
 * that, since a vector may write a number as {@code 1798761600000.0}, which a reader judges by value and a tree
 * written back would print as {@code 1.7987616E12}. So the tree is built here while the file is read, and every
 * value in it remembers the exact text it was read from; {@link #json} gives that text back.
 */
public final class Vectors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Each value read from a vector file, by identity, to the text it was read from. */
    private static final Map<JsonNode, String> TEXT = Collections.synchronizedMap(new IdentityHashMap<>());

    private Vectors() {
    }

    public static JsonNode load(String name) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return read(Files.readString(candidate, StandardCharsets.UTF_8));
            }
        }
        throw new IllegalStateException("spec/vectors/" + name + " not found above " + dir);
    }

    /**
     * A vector's value as the SDK takes it: the text the file holds for it, exactly; null stays null. Only a value
     * {@link #load} returned (or reached from one) has such text, so anything else is a test's mistake and throws.
     * Jackson shares the nodes for {@code true}, {@code false}, {@code null}, {@code ""} and small integers, so for
     * those the text is that of the value's last occurrence, which is the same JSON.
     */
    public static String json(JsonNode node) {
        if (node == null) {
            return null;
        }
        String text = TEXT.get(node);
        if (text == null) {
            throw new IllegalArgumentException("not a value read from a vector file: " + node);
        }
        return text;
    }

    /**
     * A vector's value as the SDK's own JSON value, members in the file's order, to compare with what the SDK reads.
     * A number that is not an integer within [0, 2^53 &minus; 1] throws, since no such value exists.
     */
    public static JsonValue value(JsonNode node) {
        if (node.isObject()) {
            Map<String, JsonValue> members = new LinkedHashMap<>();
            node.properties().forEach(m -> members.put(m.getKey(), value(m.getValue())));
            return new JsonValue.Obj(members);
        } else if (node.isArray()) {
            List<JsonValue> items = new ArrayList<>();
            node.forEach(item -> items.add(value(item)));
            return new JsonValue.Arr(items);
        } else if (node.isTextual()) {
            return new JsonValue.Str(node.textValue());
        } else if (node.isBoolean()) {
            return new JsonValue.Bool(node.booleanValue());
        } else if (node.isNull()) {
            return new JsonValue.Null();
        } else if (node.isIntegralNumber() && node.canConvertToLong()) {
            return new JsonValue.Int(node.longValue());
        }
        throw new IllegalArgumentException("not a value the SDK reads: " + node);
    }

    /**
     * The JCS text of a vector's value, for an input a test builds from a vector's structure (material, a proof,
     * an influence list), never for an object the case says was received, which it carries as a token.
     */
    public static String text(JsonNode node) {
        return JsonWriter.text(value(node));
    }

    /** A case's token, the bytes it says were received, as the JSON text they are, for the SDK's text API. */
    public static String tokenText(JsonNode token) {
        return new String(Base64Url.decode(token.textValue()), StandardCharsets.UTF_8);
    }

    /** The tree of a vector file's text, with each value's text recorded as it is read. */
    public static JsonNode read(String file) throws IOException {
        try (JsonParser p = MAPPER.getFactory().createParser(file)) {
            p.nextToken();
            JsonNode root = value(p, file);
            if (p.nextToken() != null) {
                throw new IOException("a vector file holds one JSON value");
            }
            return root;
        }
    }

    /**
     * The value at the parser's current token, built as a tree read would build it: a repeated name's last value
     * wins, and a scalar is read from its own text, so it is the node a tree read gives.
     */
    private static JsonNode value(JsonParser p, String file) throws IOException {
        int start = (int) p.currentTokenLocation().getCharOffset();
        JsonNode node;
        if (p.currentToken() == JsonToken.START_OBJECT) {
            ObjectNode o = JsonNodeFactory.instance.objectNode();
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String name = p.currentName();
                p.nextToken();
                o.set(name, value(p, file));
            }
            node = o;
        } else if (p.currentToken() == JsonToken.START_ARRAY) {
            ArrayNode a = JsonNodeFactory.instance.arrayNode();
            while (p.nextToken() != JsonToken.END_ARRAY) {
                a.add(value(p, file));
            }
            node = a;
        } else {
            p.finishToken();
            node = null;
        }
        String text = file.substring(start, (int) p.currentLocation().getCharOffset());
        if (node == null) {
            node = MAPPER.readTree(text);
        }
        TEXT.put(node, text);
        return node;
    }
}
