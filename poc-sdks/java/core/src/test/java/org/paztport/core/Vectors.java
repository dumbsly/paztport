// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
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
 * <p>A replay hands the SDK what a case says was received as the bytes the case carries for it (a token, a hex
 * body, a file's text), and builds every other input from the case's values ({@link #text}). Jackson only walks the
 * file.
 */
public final class Vectors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

    /**
     * A case's token, the bytes it says were received, as the JSON text they are, for the SDK's text API. Bytes that
     * are not UTF-8 throw, so the replay never repairs them on the way.
     */
    public static String tokenText(JsonNode token) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Base64Url.decode(token.textValue()))).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("a token whose bytes are not UTF-8: " + token, e);
        }
    }

    /** The tree of a vector file's text. */
    public static JsonNode read(String file) throws IOException {
        try (JsonParser p = MAPPER.getFactory().createParser(file)) {
            JsonNode root = MAPPER.readTree(p);
            if (p.nextToken() != null) {
                throw new IOException("a vector file holds one JSON value");
            }
            return root;
        }
    }
}
