// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.paztport.core.Vectors;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;

/**
 * Builds {@code spec/vectors/intent.json} and replays it. Every expected answer is written here by hand from
 * {@code spec/intent.md}; {@link #build} never calls {@link IntentFacts#parse}, {@link Intent#readRequest} or
 * {@link Intent#require} to get one, and only {@link #assertAll} does. The file holds no keys or times, so it is
 * reproduced byte for byte. The writer is opt-in, and this class is not matched by Surefire's default includes, so
 * name it: {@code (cd poc-sdks/java && mvn -q -pl core test -Dtest=IntentVectorsExport
 * -Dpaztport.exportIntentVectors=true -Dvectors.out=<repo>/poc-sdks/spec/vectors/intent.json
 * -Dsurefire.failIfNoSpecifiedTests=false)}.
 */
class IntentVectorsExport {

    private static final String ABOUT = "Paztport intent conformance vectors (spec intent.md): how an item reads, and"
            + " what the checks P1 and P2 answer for the items a service is handed under `intent`. Every answer is"
            + " written by hand from the spec. `items` gives an `item` as the text a block carries, and its `facts`:"
            + " each fact name to the JCS text of its value as a JSON string, so the integer 100 is \"100\" and the"
            + " string x is \"\\\"x\\\"\", or null when the item does not read as an intent item, whether the wire"
            + " reader refuses its text or its schema does. `requests` gives, for a service that handles a request,"
            + " whether the hand-over is `verified` and whether the service acts on `intent` (`actsOn`); when it does,"
            + " `stamps` lists each stamp of the chain in order with its signer `svc` and the `items` its block holds"
            + " under `intent`, null when the block does not name it and [] when it names it with none. `stamps` null"
            + " means nothing is handed over: with `actsOn` true there is no hand-over at all (the chain did not read,"
            + " or the service is an origin), and with `actsOn` false the service does not act on `intent`. Each item"
            + " in `stamps` is wire-valid JSON, so a block can hold it. `needs` is the names of the facts the handler"
            + " requires. `read` is the answer of check P1 over the items, `OK` or `INTENT_MISMATCH`, and"
            + " `unreadSigner` the signer of the block holding items that do not read, null when they read. `require`"
            + " is the answer of check P2 for `needs`: `OK`, `INTENT_MISSING` or `INTENT_MISMATCH`, the last when the"
            + " items of a verified hand-over do not read. `read` and `require` are what each check answers on its"
            + " own, and a request's answer is the first of `read` then `require` that is not `OK`: a receiver runs"
            + " the read first and refuses with its answer, so an unverified hand-over whose items do not read has"
            + " `require` `INTENT_MISSING` and is refused `INTENT_MISMATCH`. Cases may be added; a recorded answer"
            + " changes only with a protocol change.";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String WITH_AMOUNT = "{\"facts\":{\"amount\":100,\"order\":\"123\"}}";
    private static final String WITHOUT_AMOUNT = "{\"facts\":{\"order\":\"123\"}}";
    private static final String BOTH_NAMES = "{\"facts\":{\"amount\":100,\"order\":\"123\"}}";
    private static final String NOT_AN_ITEM = "{\"facts\":{}}";

    private static ObjectNode itemCase(String name, String item, String... namesAndTexts) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put("item", item);
        if (namesAndTexts == null) {
            c.putNull("facts");
        } else {
            ObjectNode facts = c.putObject("facts");
            for (int i = 0; i < namesAndTexts.length; i += 2) {
                facts.put(namesAndTexts[i], namesAndTexts[i + 1]);
            }
        }
        return c;
    }

    /** An item that does not read, whose {@code facts} is null. */
    private static ObjectNode unread(String name, String item) {
        return itemCase(name, item, (String[]) null);
    }

    private static ObjectNode stamp(String svc, String... items) {
        ObjectNode s = JsonNodeFactory.instance.objectNode();
        s.put("svc", svc);
        if (items == null) {
            s.putNull("items");
        } else {
            ArrayNode a = s.putArray("items");
            Arrays.stream(items).forEach(a::add);
        }
        return s;
    }

    /** A stamp whose block does not name intent. */
    private static ObjectNode unnamed(String svc) {
        return stamp(svc, (String[]) null);
    }

    private static ObjectNode request(String name, boolean verified, List<ObjectNode> stamps, List<String> needs,
            String read, String unreadSigner, String require) {
        return request(name, verified, stamps != null, stamps, needs, read, unreadSigner, require);
    }

    private static ObjectNode request(String name, boolean verified, boolean actsOn, List<ObjectNode> stamps,
            List<String> needs, String read, String unreadSigner, String require) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put("verified", verified);
        c.put("actsOn", actsOn);
        if (stamps == null) {
            c.putNull("stamps");
        } else {
            c.putArray("stamps").addAll(stamps);
        }
        ArrayNode n = c.putArray("needs");
        needs.forEach(n::add);
        c.put("read", read);
        if (unreadSigner == null) {
            c.putNull("unreadSigner");
        } else {
            c.put("unreadSigner", unreadSigner);
        }
        c.put("require", require);
        return c;
    }

    /** A request whose items read: its {@code unreadSigner} is null. */
    private static ObjectNode reads(String name, boolean verified, List<ObjectNode> stamps, List<String> needs,
            String require) {
        return request(name, verified, stamps, needs, "OK", null, require);
    }

    /** A request whose items do not read, the block of {@code signer} holding them. */
    private static ObjectNode unreads(String name, boolean verified, List<ObjectNode> stamps, List<String> needs,
            String signer, String require) {
        return request(name, verified, stamps, needs, "INTENT_MISMATCH", signer, require);
    }

    static ObjectNode build() throws IOException {
        List<String> amount = List.of("amount");
        ObjectNode out = JsonNodeFactory.instance.objectNode();
        out.put("about", ABOUT);

        ArrayNode items = out.putArray("items");
        items.add(itemCase("string", "{\"facts\":{\"customer\":\"c-42\"}}", "customer", "\"c-42\""));
        items.add(itemCase("integer", "{\"facts\":{\"amount\":100}}", "amount", "100"));
        items.add(itemCase("null", "{\"facts\":{\"note\":null}}", "note", "null"));
        items.add(itemCase("nested", "{\"facts\":{\"lines\":{\"k\":[1,\"a\"],\"z\":null}}}",
                "lines", "{\"k\":[1,\"a\"],\"z\":null}"));
        items.add(itemCase("non-ASCII text", "{\"facts\":{\"city\":\"Zürich\"}}", "city", "\"Zürich\""));
        items.add(itemCase("several facts", "{\"facts\":{\"amount\":100,\"customer\":\"c-42\",\"order\":\"123\"}}",
                "amount", "100", "customer", "\"c-42\"", "order", "\"123\""));
        items.add(unread("no facts", "{\"facts\":{}}"));
        items.add(unread("empty object", "{}"));
        items.add(unread("not an object", "[]"));
        items.add(unread("facts is an array", "{\"facts\":[]}"));
        items.add(unread("another member", "{\"facts\":{\"a\":1},\"more\":1}"));
        items.add(unread("upper-case name", "{\"facts\":{\"A\":1}}"));
        items.add(unread("empty name", "{\"facts\":{\"\":1}}"));
        items.add(unread("name of 33 characters", "{\"facts\":{\"" + "a".repeat(33) + "\":1}}"));
        items.add(unread("non-integer number", "{\"facts\":{\"a\":1.5}}"));
        items.add(unread("repeated fact", "{\"facts\":{\"a\":1,\"a\":2}}"));
        items.add(unread("not JSON", "not json"));
        items.add(unread("a space inside", "{\"facts\": {\"a\":1}}"));
        items.add(unread("members out of order", "{\"facts\":{\"b\":1,\"a\":2}}"));

        ArrayNode requests = out.putArray("requests");
        requests.add(reads("the origin states the fact", true, List.of(stamp("origin", WITH_AMOUNT)), amount, "OK"));
        requests.add(reads("the origin does not state the fact", true, List.of(stamp("origin", WITHOUT_AMOUNT)),
                amount, "INTENT_MISSING"));
        requests.add(reads("no stamp names intent", true, List.of(unnamed("origin")), amount, "INTENT_MISSING"));
        requests.add(reads("the origin names intent with no items", true, List.of(stamp("origin")), amount,
                "INTENT_MISSING"));
        requests.add(unreads("the origin holds two items", true,
                List.of(stamp("origin", WITH_AMOUNT, WITHOUT_AMOUNT)), amount, "origin", "INTENT_MISMATCH"));
        requests.add(unreads("the origin's item does not read", true, List.of(stamp("origin", NOT_AN_ITEM)), amount,
                "origin", "INTENT_MISMATCH"));
        requests.add(unreads("the origin's item has a name that is refused", true,
                List.of(stamp("origin", "{\"facts\":{\"Order\":1}}")), List.of("amount", "order"), "origin",
                "INTENT_MISMATCH"));
        requests.add(unreads("a later stamp holds an item", true,
                List.of(stamp("origin", WITH_AMOUNT), stamp("second", WITH_AMOUNT)), amount, "second",
                "INTENT_MISMATCH"));
        requests.add(reads("a later stamp names intent with no items", true,
                List.of(stamp("origin", WITH_AMOUNT), stamp("second")), amount, "OK"));
        requests.add(reads("three stamps, the origin's facts reach the receiver", true,
                List.of(stamp("origin", WITH_AMOUNT), stamp("second"), unnamed("third")), amount, "OK"));
        requests.add(unreads("three stamps, the third holds an item", true,
                List.of(stamp("origin", WITH_AMOUNT), stamp("second"), stamp("third", WITH_AMOUNT)), amount, "third",
                "INTENT_MISMATCH"));
        requests.add(reads("a hand-over not verified believes no fact", false, List.of(stamp("origin", WITH_AMOUNT)),
                amount, "INTENT_MISSING"));
        requests.add(unreads("a hand-over not verified still reads its items", false,
                List.of(stamp("origin", NOT_AN_ITEM)), List.of(), "origin", "OK"));
        requests.add(reads("a service that does not act on intent", true, null, amount, "INTENT_MISSING"));
        requests.add(reads("a service that does not act on intent, and no fact required", true, null, List.of(),
                "OK"));
        requests.add(reads("no fact required, the item has facts", true, List.of(stamp("origin", WITH_AMOUNT)),
                List.of(), "OK"));
        requests.add(reads("no fact required, no stamp names intent", true, List.of(unnamed("origin")), List.of(),
                "OK"));
        requests.add(reads("no fact required, hand-over not verified", false,
                List.of(stamp("origin", WITHOUT_AMOUNT)), List.of(), "OK"));
        requests.add(unreads("no fact required, the item does not read", true, List.of(stamp("origin", NOT_AN_ITEM)),
                List.of(), "origin", "OK"));
        requests.add(reads("two facts required, both stated", true, List.of(stamp("origin", BOTH_NAMES)),
                List.of("amount", "order"), "OK"));
        requests.add(reads("two facts required, one stated", true, List.of(stamp("origin", WITHOUT_AMOUNT)),
                List.of("amount", "order"), "INTENT_MISSING"));

        requests.add(request("no hand-over", false, true, null, amount, "OK", null, "INTENT_MISSING"));
        requests.add(request("no hand-over, no fact required", false, true, null, List.of(), "OK", null, "OK"));
        requests.add(unreads("a hand-over not verified, the origin's item does not read", false,
                List.of(stamp("origin", NOT_AN_ITEM)), amount, "origin", "INTENT_MISSING"));
        requests.add(reads("the origin states the fact as null", true,
                List.of(stamp("origin", "{\"facts\":{\"amount\":null}}")), amount, "OK"));

        // Replay what was just built, read back from the text it is written as.
        assertAll(Vectors.read(new String(render(out), StandardCharsets.UTF_8)));
        return out;
    }

    /** Replays every case against the SDK; the expected answers are the file's own. */
    static void assertAll(JsonNode vectors) {
        for (JsonNode c : vectors.get("items")) {
            String name = c.get("name").asText();
            String item = c.get("item").asText();
            if (c.get("facts").isNull()) {
                assertThrows(IllegalArgumentException.class, () -> IntentFacts.parse(item), name);
                continue;
            }
            IntentFacts facts = IntentFacts.parse(item);
            Set<String> want = new TreeSet<>();
            c.get("facts").properties().forEach(m -> {
                want.add(m.getKey());
                assertEquals(m.getValue().asText(), facts.json(m.getKey()), name + ": " + m.getKey());
            });
            assertEquals(want, facts.names(), name);
        }
        for (JsonNode c : vectors.get("requests")) {
            String name = c.get("name").asText();
            boolean none = c.get("actsOn").asBoolean() && c.get("stamps").isNull();
            HandOver handOver = none ? null : handOver(c);
            List<String> needs = new ArrayList<>();
            c.get("needs").forEach(n -> needs.add(n.asText()));
            RequestIntent read = Intent.readRequest(handOver == null ? null : handOver.under(Intent.NAME));
            assertEquals(c.get("read").asText(), read.reads() ? "OK" : read.reason().name(), name + ": read");
            assertEquals(c.get("unreadSigner").isNull() ? null : c.get("unreadSigner").asText(), read.unreadSigner(),
                    name + ": unreadSigner");
            assertEquals(ReasonCode.valueOf(c.get("require").asText()), Intent.require(handOver, needs),
                    name + ": require");
        }
    }

    /** What the verifier hands the service the case describes. */
    private static HandOver handOver(JsonNode c) {
        boolean acts = c.get("actsOn").asBoolean();
        List<Stamp> stamps = new ArrayList<>();
        List<Block> blocks = new ArrayList<>();
        if (acts) {
            for (JsonNode s : c.get("stamps")) {
                stamps.add(new Stamp(s.get("svc").asText(), "i", "r", 1L, "s", "rcv", "b", "", "", "sig"));
                if (s.get("items").isNull()) {
                    blocks.add(Block.EMPTY);
                } else {
                    List<String> texts = new ArrayList<>();
                    s.get("items").forEach(t -> texts.add(t.asText()));
                    blocks.add(Block.of(Map.of(Intent.NAME, texts), List.of()));
                }
            }
        } else {
            stamps.add(new Stamp("origin", "i", "r", 1L, "s", "rcv", "b", "", "", "sig"));
            blocks.add(Block.EMPTY);
        }
        ExtensionSettings settings = acts ? ExtensionSettings.of(Set.of(Intent.NAME), null) : ExtensionSettings.NONE;
        return new HandOver(c.get("verified").asBoolean(), stamps, blocks, settings);
    }

    /** The exact bytes the writer puts in the file: indented JSON and a final newline. */
    static byte[] render(JsonNode built) throws IOException {
        byte[] json = MAPPER.copy().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsBytes(built);
        byte[] out = Arrays.copyOf(json, json.length + 1);
        out[json.length] = '\n';
        return out;
    }

    /** The committed file's bytes, found by walking up from the working directory as {@link Vectors} does. */
    static byte[] loadBytes(String name) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return Files.readAllBytes(candidate);
            }
        }
        throw new IllegalStateException("spec/vectors/" + name + " not found above " + dir);
    }

    @Test
    @EnabledIfSystemProperty(named = "paztport.exportIntentVectors", matches = "true")
    void export() throws IOException {
        Path file = Path.of(System.getProperty("vectors.out", "target/intent.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, render(build()));
    }
}
