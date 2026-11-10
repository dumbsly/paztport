// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.paztport.core.Vectors;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

/**
 * Builds {@code spec/vectors/http-v3.json} and replays it. It is deterministic: the
 * clock, rid and timestamps are fixed, the one new key is derived by {@code v3.json}'s rule, and Ed25519 signs
 * deterministically, so {@link #build} reproduces the committed bytes and {@code VectorsHttpV3Test} pins them.
 * The writer is opt-in. This class is not matched by Surefire's default
 * includes, so name it: {@code (cd poc-sdks/java && mvn -q -pl http -am test -Dtest=VectorsHttpV3Export
 * -Dpaztport.exportHttpVectors=true -Dvectors.out=<repo>/poc-sdks/spec/vectors/http-v3.json
 * -Dsurefire.failIfNoSpecifiedTests=false)}. {@link #build} replays every case it records, so an export can
 * never record a wrong answer.
 */
class VectorsHttpV3Export {

    private static final String ABOUT = "Paztport v3-over-HTTP conformance vectors. The keys, the `mesh` policy and"
            + " its proofs are the ones in v3.json, by name; only the `payment` key is new, derived by v3.json's rule"
            + " (seed = SHA-256(utf8(\"paztport-v3-vector-key:payment\")), the same PKCS#8 and SPKI encodings, both"
            + " base64url). resultHash maps a status and body (hex) to the result hash. requestBinding maps a method,"
            + " a target (the raw path plus `?` and the raw query when there is one) and a body (hex) to the request"
            + " binding. headerNames maps a header name to whether it is Paztport's: it begins with `X-Path-`, compared"
            + " case-insensitively over ASCII. A responses case is a request chain `sent` from gateway to orders to"
            + " payment and the `responseHeader` payment returned; the caller `orders` checks it against `status` and"
            + " `body` (hex) with the proof the mesh policy holds for `proofRoute`, except where said below, as a"
            + " verifier whose policy window ends at `policyNotAfter` and whose clock reads `now`, running the check"
            + " `uses` times against one"
            + " nonce cache of nonceTtlMs that already holds `spent` (none when absent), and expects the last result,"
            + " with `labels` empty unless the reason is OK."
            + " boundaryInfluence is the influence an egress sends to another organisation: under the boundary `key`"
            + " (SHA-256(utf8(\"paztport-http-v3-vector-boundary-key\")), base64url), for `rid`, the partner entry"
            + " `rcv` and the `egress`, the `input` entries reduce to `reduced`, with one salt (base64url) per"
            + " (cls, owner) group in `salts`; each `openings` case is a `sent` entry and an `opening`, with its"
            + " JCS bytes in `body` (hex), which the replay reads, and `opens` says whether it opens. Ed25519 is"
            + " deterministic, so the file is reproduced byte for byte. Java writes and replays this"
            + " file; Go replays every section; the TypeScript SDK does not speak v3 over HTTP, so it"
            + " does not replay it. The three responses cases before the last three run on the `ops` policy: the"
            + " chain names the operation each hop invokes (`orders#createOrder`, then `payment#charge`) and the proof"
            + " is for that route. The last three run on `rules.material.shop-keys` and, unlike the others, are a"
            + " chain `sent` from gateway to orders naming `orders#reserve` and the `responseHeader` orders returned,"
            + " which the caller `gateway` checks, each with `key`, the key value of the target sent. `operations`"
            + " holds `table`, an"
            + " operation table as a `file` (its text) and `value`, with its `opsHash` and the `route` a root covers"
            + " it as; `shared`, payment's table, an entrance with two operations told apart by a query condition, in"
            + " the same form; `keyed`, a table whose operations declare keys, in the same form; `refused`, table"
            + " files a reader refuses; `match`, a method, a raw path and a raw query (null for none) against a table"
            + " `file` and the operation name it gives, null for none; `keys`, cases giving a call's operation in"
            + " `keyed` and its key value, null for none; and `receive`, a request"
            + " entered at `orders` through the HTTP receiver under enforce, against a nonce cache that already holds"
            + " `spent` (none when absent), whose chain's"
            + " first stamp names `orders` or an operation of it, with the `operation` the framework dispatches to"
            + " (null for none) and the `refusal` it expects (null when the request is served). Every `receive`"
            + " case on the `ops` policy carries the proof of `gateway/orders#createOrder`, whatever its chain names;"
            + " the receive and"
            + " responses cases naming `material` run on `rules.material`, the receiver holding `keyed` as its own"
            + " table.";

    private static final long GATEWAY_TS = 1_767_225_598_500L;
    private static final long ORDERS_TS = 1_767_225_599_500L;
    private static final long RESPONSE_TS = 1_767_225_599_800L;
    private static final long NOW = 1_767_225_600_000L;
    /**
     * The policy window the responses cases check under, 2100-01-01: past their {@code now}. The "policy expired"
     * case ends its own window 1 ms before it.
     */
    private static final long MESH_NOT_AFTER = 4_102_444_800_000L;
    private static final String RID = "rid-http-1";
    private static final String ROUTE = "gateway/orders/payment";
    private static final byte[] REQUEST_BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_BODY = "{\"paid\":true}".getBytes(StandardCharsets.UTF_8);
    private static final String KEY_PREFIX = "302e020100300506032b657004220420";
    private static final byte[] BOUNDARY_KEY =
            Crypto.sha256("paztport-http-v3-vector-boundary-key".getBytes(StandardCharsets.UTF_8));
    private static final String PARTNER_ENTRY = "psp";
    private static final String EGRESS = "payment";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A committed vector file, read by core's loader so each value reaches the SDK as the file writes it. */
    static JsonNode load(String name) throws IOException {
        return Vectors.load(name);
    }

    /** The key v3.json's rule gives {@code name}: the seed is a hash of the name, the public key follows from it. */
    static KeyPair derive(String name) {
        byte[] seed = Crypto.sha256(("paztport-v3-vector-key:" + name).getBytes(StandardCharsets.UTF_8));
        SecureRandom fixed = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                System.arraycopy(seed, 0, bytes, 0, bytes.length);
            }
        };
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
            gen.initialize(NamedParameterSpec.ED25519, fixed);
            KeyPair pair = gen.generateKeyPair();
            assertEquals(KEY_PREFIX + HexFormat.of().formatHex(seed),
                    HexFormat.of().formatHex(Crypto.encodePrivateKey(pair.getPrivate())), "derived key " + name);
            return pair;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    /** A value the SDK wrote as JSON text, as a tree to place in a vector. */
    private static JsonNode tree(String json) {
        return VectorsHttpRules.tree(json);
    }

    private static ArrayNode stampsJson(List<Stamp> stamps) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        stamps.forEach(s -> a.add(tree(s.toJson())));
        return a;
    }

    private static ArrayNode labelsJson(List<ContentLabel> labels) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        labels.forEach(l -> a.add(tree(l.toJson())));
        return a;
    }

    static ObjectNode build() throws IOException {
        JsonNode core = load("v3.json");
        KeyPair payment = derive("payment");
        PrivateKey gatewayKey =
                Crypto.decodePrivateKey(Base64Url.decode(core.get("keys").get("gateway").get("priv").asText()));
        PrivateKey ordersKey =
                Crypto.decodePrivateKey(Base64Url.decode(core.get("keys").get("orders").get("priv").asText()));
        JsonNode proof = core.get("policies").get("mesh").get("proofs").get(ROUTE);
        MerkleProof sentProof = MerkleProof.parse(Vectors.text(proof));

        // The request chain gateway -> orders -> payment, exactly as Stamper builds it in a mesh.
        Stamper.Stamped toOrders = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders", "bind-gateway-to-orders", List.of(), null);
        Stamper.Stamped toPayment = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> ORDERS_TS)
                .next(toOrders.chain(), "payment", RequestBinding.compute("POST", "/pay", REQUEST_BODY), List.of(),
                        null);
        List<Stamp> sent = toPayment.chain();
        Stamper responder = new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> RID, () -> RESPONSE_TS);

        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-receipt-1", "alice"));
        String okHash = HttpWire.resultHash(200, RESPONSE_BODY);
        Stamp okStamp = responder.respond(sent, okHash, RID, labels);
        String okHeader = HttpWire.encodeResponse(okStamp, labels);
        // A properly signed response, but to the gateway rather than to the caller that sent the request.
        Stamp toGateway = Stamp.sign("payment", "pay-1", RID, RESPONSE_TS, "", "gateway",
                responseBinding(okHash, labels), "", sent.get(sent.size() - 1).sig(), payment.getPrivate());

        ObjectNode out = JsonNodeFactory.instance.objectNode();
        out.put("about", ABOUT);
        ObjectNode keys = out.putObject("keys");
        ObjectNode pay = keys.putObject("payment");
        pay.put("pub", Base64Url.encode(Crypto.encodePublicKey(payment.getPublic())));
        pay.put("priv", Base64Url.encode(Crypto.encodePrivateKey(payment.getPrivate())));

        ArrayNode hashes = out.putArray("resultHash");
        for (Object[] c : new Object[][] {{200, ""}, {200, hex(RESPONSE_BODY)}, {404, hex(RESPONSE_BODY)},
                {500, hex("{\"error\":\"Zoë 😀\"}".getBytes(StandardCharsets.UTF_8))}}) {
            byte[] body = HexFormat.of().parseHex((String) c[1]);
            ObjectNode o = hashes.addObject();
            o.put("status", (int) c[0]);
            o.put("body", (String) c[1]);
            o.put("hash", HttpWire.resultHash((int) c[0], body));
        }

        ArrayNode bindings = out.putArray("requestBinding");
        for (String[] c : new String[][] {{"POST", "/pay", hex(REQUEST_BODY)}, {"GET", "/search", ""},
                {"GET", "/search?q=a", ""}, {"GET", "/search?q=b", ""}, {"GET", "/search?q=caf%C3%A9&n=1", ""},
                {"PUT", "/pé/😀?x=😀", hex("{\"name\":\"Zoë\"}".getBytes(StandardCharsets.UTF_8))}}) {
            ObjectNode o = bindings.addObject();
            o.put("method", c[0]);
            o.put("target", c[1]);
            o.put("body", c[2]);
            o.put("bind", RequestBinding.compute(c[0], c[1], HexFormat.of().parseHex(c[2])));
        }

        ArrayNode headerNames = out.putArray("headerNames");
        for (String name : new String[] {"X-Path-Chain", "x-path-chain", "X-PATH-PROOF", "X-Path-Influence",
                "X-Path-Session", "X-Path-Response", "X-Path-Future", "X-Path-", "X-Path", "X-Pathology",
                "X-Path_Chain", "XX-Path-Chain", "", "X\u2010Path\u2010Chain", "X-P\u0430th-Chain"}) {
            ObjectNode o = headerNames.addObject();
            o.put("header", name);
            o.put("paztport", PaztportHeaders.isPaztport(name));
        }

        ArrayNode responses = out.putArray("responses");
        responses.add(responseCase("response ok", sent, okHeader, 200, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, ReasonCode.OK, "payment", "pay-1", labels, okHash));
        responses.add(responseCase("response to wrong receiver", sent, HttpWire.encodeResponse(toGateway, labels), 200,
                RESPONSE_BODY, 1, MESH_NOT_AFTER, ReasonCode.BINDING_MISMATCH, "", "", List.of(), okHash));
        responses.add(responseCase("labels altered", sent, HttpWire.encodeResponse(okStamp,
                List.of(new ContentLabel(InfluenceClass.PUBLIC, "cid-receipt-1", null))), 200, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, ReasonCode.BINDING_MISMATCH, "", "", List.of(), okHash));
        responses.add(responseCase("status altered", sent, okHeader, 500, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, ReasonCode.BINDING_MISMATCH, "", "", List.of(),
                HttpWire.resultHash(500, RESPONSE_BODY)));
        responses.add(responseCase("replayed response", sent, okHeader, 200, RESPONSE_BODY, 2,
                MESH_NOT_AFTER, ReasonCode.REPLAY, "", "", List.of(), okHash));
        responses.add(responseCase("policy expired", sent, okHeader, 200, RESPONSE_BODY, 1,
                NOW - 1, ReasonCode.POLICY_EXPIRED, "", "", List.of(), okHash));
        responses.forEach(c -> ((ObjectNode) c).put("proofRoute", ROUTE));
        operationsResponses(gatewayKey, ordersKey, payment, labels, okHash).forEach(responses::add);
        keyedResponses(gatewayKey, ordersKey, labels, okHash).forEach(responses::add);
        out.set("rules", VectorsHttpRules.build(out, core));

        out.set("boundaryInfluence", boundaryInfluence());
        out.set("operations", operations(core, out.get("rules"), gatewayKey));

        // Replay what was just built, read back from the text it is written as, so an export can never record a
        // wrong answer.
        assertAll(Vectors.read(new String(render(out), StandardCharsets.UTF_8)), core);
        return out;
    }

    /**
     * Two private entries of alice's, a third-party ticket and private data with no owner, so the cases cover a
     * group of two, an owned group and the no-owner groups. The extra-original case adds an alice entry the sender
     * never committed to.
     */
    private static ObjectNode boundaryInfluence() {
        List<InfluenceEntry> input = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-1", "cid-order-1", "alice"),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:cards", "h-card-1", null, "alice"),
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "h-ticket-1", "cid-ticket-1", null),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:ledger", "h-ledger-1", null, null));
        List<InfluenceEntry> reduced = BoundaryInfluence.reduce(input, BOUNDARY_KEY, RID, PARTNER_ENTRY, EGRESS);
        ObjectNode b = JsonNodeFactory.instance.objectNode();
        b.put("key", Base64Url.encode(BOUNDARY_KEY));
        b.put("rid", RID);
        b.put("rcv", PARTNER_ENTRY);
        b.put("egress", EGRESS);
        b.set("input", tree(Influence.toJson(input)));
        ArrayNode salts = b.putArray("salts");
        for (InfluenceEntry e : reduced) {
            ObjectNode s = salts.addObject();
            s.put("cls", e.cls().wire());
            if (e.owner() != null) {
                s.put("owner", e.owner());
            }
            s.put("salt", boundarySalt(e));
        }
        b.set("reduced", tree(Influence.toJson(reduced)));
        InfluenceEntry aliceSent = reduced.stream().filter(e -> "alice".equals(e.owner())).findFirst().orElseThrow();
        List<InfluenceEntry> aliceOriginals = input.stream().filter(e -> "alice".equals(e.owner())).toList();
        List<InfluenceEntry> withExtra = new ArrayList<>(aliceOriginals);
        withExtra.add(new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-2", null, "alice"));
        ArrayNode openings = b.putArray("openings");
        openings.add(openingCase("genuine opening", aliceSent, aliceOriginals, true));
        openings.add(openingCase("extra original", aliceSent, withExtra, false));
        return b;
    }

    private static String boundarySalt(InfluenceEntry sent) {
        return Base64Url.encode(BoundaryInfluence.salt(BOUNDARY_KEY, RID, PARTNER_ENTRY, sent.cls(), sent.owner()));
    }

    private static ObjectNode openingCase(String name, InfluenceEntry sent, List<InfluenceEntry> originals,
            boolean opens) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.set("sent", tree(sent.toJson()));
        String opening = new BoundaryInfluence.Opening(sent.cls(), sent.owner(), boundarySalt(sent), originals)
                .toJson();
        c.set("opening", tree(opening));
        c.put("body", VectorsHttpRules.hex(opening.getBytes(StandardCharsets.UTF_8)));
        c.put("opens", opens);
        return c;
    }

    private static void assertBoundaryInfluence(JsonNode b) {
        byte[] key = Base64Url.decode(b.get("key").asText());
        String rid = b.get("rid").asText();
        String rcv = b.get("rcv").asText();
        List<InfluenceEntry> reduced = BoundaryInfluence.reduce(Influence.parse(Vectors.text(b.get("input"))), key,
                rid, rcv, b.get("egress").asText());
        assertEquals(b.get("reduced"), tree(Influence.toJson(reduced)), "boundary reduced");
        assertEquals(b.get("salts").size(), reduced.size(), "a salt per group");
        for (JsonNode s : b.get("salts")) {
            InfluenceClass cls = InfluenceClass.fromWire(s.get("cls").asText());
            String owner = s.has("owner") ? s.get("owner").asText() : null;
            assertEquals(s.get("salt").asText(), Base64Url.encode(BoundaryInfluence.salt(key, rid, rcv, cls, owner)),
                    "boundary salt " + s);
        }
        for (JsonNode c : b.get("openings")) {
            InfluenceEntry sent = Influence.parse("[" + Vectors.text(c.get("sent")) + "]").get(0);
            BoundaryInfluence.Opening opening = BoundaryInfluence.Opening.parse(VectorsHttpRules.unhex(c.get("body")));
            assertEquals(c.get("opening"), tree(opening.toJson()), "opening body " + c.get("name").asText());
            assertEquals(c.get("opens").asBoolean(), BoundaryInfluence.opens(sent, opening), c.get("name").asText());
        }
    }

    private static final String OPS_ROUTE = "gateway/orders#createOrder/payment#charge";

    /**
     * Responses on the route through operations: payment's response stamp names {@code orders}, the caller. The
     * response's nonce key names the operation the sent chain invokes, so another operation's spent key does not
     * refuse it and its own does.
     */
    private static List<ObjectNode> operationsResponses(PrivateKey gatewayKey, PrivateKey ordersKey, KeyPair payment,
            List<ContentLabel> labels, String okHash) {
        Stamper.Stamped toOrders = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders#createOrder", "bind-gateway-to-orders", List.of(), null);
        Stamper.Stamped toPayment = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> ORDERS_TS)
                .next(toOrders.chain(), "payment#charge", RequestBinding.compute("POST", "/pay", REQUEST_BODY),
                        List.of(), null);
        List<Stamp> sent = toPayment.chain();
        Stamp ok = new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> RID, () -> RESPONSE_TS)
                .respond(sent, okHash, RID, labels);
        String header = HttpWire.encodeResponse(ok, labels);
        ObjectNode c = responseCase("a response on a route through operations", sent, header, 200, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, ReasonCode.OK, "payment", "pay-1", labels, okHash);
        ObjectNode other = responseCase("another operation's response key spent", sent, header, 200, RESPONSE_BODY,
                1, MESH_NOT_AFTER, ReasonCode.OK, "payment", "pay-1", labels, okHash);
        other.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|payment#refund|resp"));
        ObjectNode own = responseCase("this operation's response key spent", sent, header, 200, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, ReasonCode.REPLAY, "", "", List.of(), okHash);
        own.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|payment#charge|resp"));
        List<ObjectNode> cases = List.of(c, other, own);
        cases.forEach(o -> {
            o.put("policy", "ops");
            o.put("proofRoute", OPS_ROUTE);
        });
        return cases;
    }

    /** The route through orders' keyed operation {@code reserve}, which {@code rules.material.shop-keys} covers. */
    static final String KEYED_ROUTE = "gateway/orders#reserve";
    private static final String KEYED_TARGET = "/items/A1/reserve";

    /**
     * Responses from the item {@code A1} of orders' keyed operation {@code reserve} to the gateway, on
     * {@code rules.material.shop-keys}. The response's nonce key holds the key value of the target sent, so another
     * item's spent key does not refuse it and its own does.
     */
    private static List<ObjectNode> keyedResponses(PrivateKey gatewayKey, PrivateKey ordersKey,
            List<ContentLabel> labels, String okHash) {
        List<Stamp> sent = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders#reserve", RequestBinding.compute("POST", KEYED_TARGET, REQUEST_BODY),
                        List.of(), null).chain();
        Stamp ok = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> RESPONSE_TS)
                .respond(sent, okHash, RID, labels);
        String header = HttpWire.encodeResponse(ok, labels);
        ObjectNode c = keyedResponse("a response from an item of a keyed operation", sent, header, ReasonCode.OK,
                "orders", "ord-1", labels, okHash);
        ObjectNode other = keyedResponse("another item's response key spent", sent, header, ReasonCode.OK, "orders",
                "ord-1", labels, okHash);
        other.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|orders#reserve|B2|resp"));
        ObjectNode own = keyedResponse("this item's response key spent", sent, header, ReasonCode.REPLAY, "", "",
                List.of(), okHash);
        own.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|orders#reserve|A1|resp"));
        List<ObjectNode> cases = List.of(c, other, own);
        cases.forEach(o -> o.put("proofRoute", KEYED_ROUTE));
        return cases;
    }

    private static ObjectNode keyedResponse(String name, List<Stamp> sent, String header, ReasonCode reason,
            String suspectSvc, String suspectInst, List<ContentLabel> labels, String okHash) {
        return responseCase(name, "material", "shop-keys", sent, "gateway", "A1", header, 200, RESPONSE_BODY, 1,
                MESH_NOT_AFTER, reason, suspectSvc, suspectInst, labels, okHash);
    }

    private static OperationTable ordersTable() {
        return new OperationTable("orders", List.of(
                new OperationTable.Operation("createOrder", "POST", "/orders"),
                new OperationTable.Operation("findOrders", "GET", "/orders"),
                new OperationTable.Operation("getOrder", "GET", "/orders/{}"),
                new OperationTable.Operation("search", "GET", "/orders/search")));
    }

    private static String tableFile(String service, String v, String... operations) {
        return "{\"operations\":[" + String.join(",", operations) + "],\"service\":\"" + service
                + "\",\"v\":" + v + "}";
    }

    private static String tableOp(String method, String name, String template) {
        return "{\"method\":\"" + method + "\",\"name\":\"" + name + "\",\"template\":\"" + template + "\"}";
    }

    private static String tableOpQuery(String name, String template, String query) {
        return "{\"method\":\"POST\",\"name\":\"" + name + "\",\"query\":" + query + ",\"template\":\""
                + template + "\"}";
    }

    /** payment's table, {@code operations.shared}: an entrance with two operations told apart by a query. */
    static OperationTable paymentTable() {
        return new OperationTable("payment", List.of(
                new OperationTable.Operation("charge", "POST", "/charge"),
                new OperationTable.Operation("refund", "POST", "/charge",
                        new OperationTable.Condition("mode", "refund")),
                new OperationTable.Operation("pay", "POST", "/pay")));
    }

    /**
     * orders' table, {@code operations.keyed}, whose operations declare keys: a segment, a query parameter and a
     * segment with a longer limit, beside one with no key.
     */
    static OperationTable keyedTable() {
        return new OperationTable("orders", List.of(
                new OperationTable.Operation("reserve", "POST", "/items/{}/reserve", null,
                        OperationTable.Key.segment(1)),
                new OperationTable.Operation("getLine", "GET", "/lines", null, OperationTable.Key.query("line")),
                new OperationTable.Operation("getRecord", "GET", "/records/{}", null,
                        new OperationTable.Key(1, null, 256)),
                new OperationTable.Operation("createOrder", "POST", "/orders")));
    }

    /** A table file of orders' {@code reserve} alone, with the key text {@code key}. */
    private static String reserve(String key) {
        return tableFile("orders", "1", tableOpKey("POST", "reserve", "/items/{}/reserve", key));
    }

    private static String tableOpKey(String method, String name, String template, String key) {
        return "{\"key\":" + key + ",\"method\":\"" + method + "\",\"name\":\"" + name + "\",\"template\":\""
                + template + "\"}";
    }

    /** A table in the form {@code operations} gives one: its file, its value, its hash and its route. */
    private static ObjectNode tableJson(OperationTable t) {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("file", t.toFile());
        o.set("value", tree(t.toFile()));
        o.put("opsHash", t.hash());
        ArrayNode route = o.putArray("route");
        t.route().forEach(route::add);
        return o;
    }

    private static void assertTable(JsonNode table, String name) {
        OperationTable t = OperationTable.read(table.get("file").asText());
        assertEquals(table.get("opsHash").asText(), t.hash(), name + " hash");
        assertEquals(table.get("route"), JsonNodeFactory.instance.arrayNode().addAll(
                t.route().stream().map(JsonNodeFactory.instance::textNode).toList()), name + " route");
        assertEquals(table.get("value"), tree(t.toFile()), name + " value");
        assertEquals(table.get("file").asText(), t.toFile(), name + " file");
    }

    private static ObjectNode operations(JsonNode core, JsonNode rules, PrivateKey gatewayKey) {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        OperationTable orders = ordersTable();
        o.set("table", tableJson(orders));
        OperationTable payment = paymentTable();
        o.set("shared", tableJson(payment));
        OperationTable keyed = keyedTable();
        o.set("keyed", tableJson(keyed));

        String create = tableOp("POST", "createOrder", "/orders");
        String charge = tableOp("POST", "charge", "/charge");
        ArrayNode refused = o.putArray("refused");
        String[][] refusals = {
            {"an operation name holding #", tableFile("orders", "1", tableOp("POST", "create#Order", "/orders"))},
            {"two operations with one name",
                tableFile("orders", "1", create, tableOp("GET", "createOrder", "/orders/{}"))},
            {"two operations with one method and template",
                tableFile("orders", "1", create, tableOp("POST", "other", "/orders"))},
            {"a template without a leading slash", tableFile("orders", "1", tableOp("POST", "x", "orders"))},
            {"a template with an empty segment", tableFile("orders", "1", tableOp("POST", "x", "/orders//x"))},
            {"a named path parameter", tableFile("orders", "1", tableOp("POST", "x", "/orders/{id}"))},
            {"a parameter inside a segment", tableFile("orders", "1", tableOp("POST", "x", "/a{}"))},
            {"a literal holding ?", tableFile("orders", "1", tableOp("POST", "x", "/a?b"))},
            {"a lowercase method", tableFile("orders", "1", tableOp("get", "x", "/orders"))},
            {"no operations", tableFile("orders", "1")},
            {"version 2", tableFile("orders", "2", create)},
            {"a service name holding #", tableFile("a#b", "1", create)},
            {"an extra member on the table",
                "{\"extra\":1,\"operations\":[" + create + "],\"service\":\"orders\",\"v\":1}"},
            {"an extra member on an operation", tableFile("orders", "1",
                "{\"extra\":1,\"method\":\"POST\",\"name\":\"x\",\"template\":\"/\"}")},
            {"a query with two members", tableFile("payment", "1", charge,
                tableOpQuery("refund", "/charge", "{\"mode\":\"refund\",\"kind\":\"x\"}"))},
            {"a query value with a reserved character", tableFile("payment", "1", charge,
                tableOpQuery("refund", "/charge", "{\"mode\":\"re/fund\"}"))},
            {"an empty query value", tableFile("payment", "1", charge,
                tableOpQuery("refund", "/charge", "{\"mode\":\"\"}"))},
            {"a query that is not an object", tableFile("payment", "1", charge,
                tableOpQuery("refund", "/charge", "\"mode=refund\""))},
            {"conditions on one entrance naming different parameters", tableFile("payment", "1",
                tableOpQuery("refund", "/charge", "{\"mode\":\"refund\"}"),
                tableOpQuery("cancel", "/charge", "{\"kind\":\"x\"}"))},
            {"two operations of one entrance with one condition", tableFile("payment", "1",
                tableOpQuery("refund", "/charge", "{\"mode\":\"refund\"}"),
                tableOpQuery("cancel", "/charge", "{\"mode\":\"refund\"}"))},
            {"a key with a segment and a query", reserve("{\"query\":\"line\",\"segment\":1}")},
            {"a key with neither a segment nor a query", reserve("{\"maxLength\":64}")},
            {"an extra member on a key", reserve("{\"extra\":1,\"segment\":1}")},
            {"a key segment of 0", reserve("{\"segment\":0}")},
            {"a key segment past the template's parameters", reserve("{\"segment\":2}")},
            {"a key segment on a template with no parameter",
                tableFile("orders", "1", tableOpKey("POST", "createOrder", "/orders", "{\"segment\":1}"))},
            {"a key segment that is not an integer", reserve("{\"segment\":\"1\"}")},
            {"a key query name with a reserved character",
                tableFile("orders", "1", tableOpKey("GET", "getLine", "/lines", "{\"query\":\"li/ne\"}"))},
            {"an empty key query name",
                tableFile("orders", "1", tableOpKey("GET", "getLine", "/lines", "{\"query\":\"\"}"))},
            {"a key query naming its entrance's condition parameter", tableFile("payment", "1",
                tableOpKey("POST", "charge", "/charge", "{\"query\":\"mode\"}"),
                tableOpQuery("refund", "/charge", "{\"mode\":\"refund\"}"))},
            {"a key maxLength of 0", reserve("{\"maxLength\":0,\"segment\":1}")},
            {"a key maxLength of 1025", reserve("{\"maxLength\":1025,\"segment\":1}")},
            {"a key maxLength that is not an integer", reserve("{\"maxLength\":\"128\",\"segment\":1}")},
            {"a key that is not an object", reserve("1")}};
        for (String[] r : refusals) {
            ObjectNode c = refused.addObject();
            c.put("name", r[0]);
            c.put("file", r[1]);
            c.put("expected", "refused");
        }

        String two = new OperationTable("orders", List.of(
                new OperationTable.Operation("x", "GET", "/a/{}/c"),
                new OperationTable.Operation("y", "GET", "/a/b/{}"))).toFile();
        ArrayNode match = o.putArray("match");
        String[][] matches = {
            {orders.toFile(), "GET", "/orders/search", null, "search"},
            {orders.toFile(), "GET", "/orders/123", null, "getOrder"},
            {orders.toFile(), "GET", "/orders", null, "findOrders"},
            {orders.toFile(), "POST", "/orders", null, "createOrder"},
            {orders.toFile(), "GET", "/orders/a%2Fb", null, "getOrder"},
            {orders.toFile(), "GET", "/orders/", null, null},
            {orders.toFile(), "GET", "/orders/123/items", null, null},
            {orders.toFile(), "get", "/orders", null, null},
            {orders.toFile(), "DELETE", "/orders", null, null},
            {two, "GET", "/a/b/c", null, "y"},
            {payment.toFile(), "POST", "/charge", "mode=refund", "refund"},
            {payment.toFile(), "POST", "/charge", null, "charge"},
            {payment.toFile(), "POST", "/charge", "mode=x", "charge"},
            {payment.toFile(), "POST", "/charge", "other=1", "charge"},
            {payment.toFile(), "POST", "/charge", "other=1&mode=refund", "refund"},
            {payment.toFile(), "POST", "/charge", "mode=refund&mode=refund", null},
            {payment.toFile(), "POST", "/charge", "mode=%72efund", "charge"}};
        for (String[] m : matches) {
            ObjectNode c = match.addObject();
            c.put("table", m[0]);
            c.put("method", m[1]);
            c.put("path", m[2]);
            if (m[3] == null) {
                c.putNull("query");
            } else {
                c.put("query", m[3]);
            }
            if (m[4] == null) {
                c.putNull("expected");
            } else {
                c.put("expected", m[4]);
            }
        }

        ArrayNode keys = o.putArray("keys");
        String longest = "k".repeat(OperationTable.Key.DEFAULT_MAX_LENGTH);
        String longer = "k".repeat(200);
        String[][] keyCases = {
            {"a segment key", "POST", KEYED_TARGET, null, "reserve", "A1"},
            {"a query key", "GET", "/lines", "line=L7", "getLine", "L7"},
            {"a percent-encoded segment", "POST", "/items/%41/reserve", null, "reserve", null},
            {"a percent-encoded query value", "GET", "/lines", "line=%4C7", "getLine", null},
            {"a dot segment", "POST", "/items/./reserve", null, "reserve", null},
            {"a dot-dot segment", "POST", "/items/../reserve", null, "reserve", null},
            {"a key of 128 characters", "POST", "/items/" + longest + "/reserve", null, "reserve", longest},
            {"a key of 129 characters", "POST", "/items/" + longest + "k/reserve", null, "reserve", null},
            {"a key of 200 characters under maxLength 256", "GET", "/records/" + longer, null, "getRecord", longer},
            {"a query key absent", "GET", "/lines", null, "getLine", null},
            {"a query key repeated", "GET", "/lines", "line=L7&line=L8", "getLine", null},
            {"a query key with no value", "GET", "/lines", "line", "getLine", null},
            {"a query key repeated under an encoded name", "GET", "/lines", "%6Cine=B&line=L7", "getLine", null},
            {"a query holding a semicolon", "GET", "/lines", "x=1;line=B&line=L7", "getLine", null},
            {"an operation with no key", "POST", "/orders", null, "createOrder", null}};
        for (String[] k : keyCases) {
            ObjectNode c = keys.addObject();
            c.put("name", k[0]);
            c.put("table", keyed.toFile());
            c.put("method", k[1]);
            c.put("path", k[2]);
            if (k[3] == null) {
                c.putNull("query");
            } else {
                c.put("query", k[3]);
            }
            ObjectNode e = c.putObject("expected");
            e.put("operation", k[4]);
            if (k[5] == null) {
                e.putNull("key");
            } else {
                e.put("key", k[5]);
            }
        }

        ArrayNode receive = o.putArray("receive");
        receive.add(receiveCase("the operation the chain names", core, gatewayKey, "orders#createOrder",
                "createOrder", null));
        ObjectNode otherSpent = receiveCase("another operation's request key spent", core, gatewayKey,
                "orders#createOrder", "createOrder", null);
        otherSpent.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|gateway|orders#getOrder|req"));
        receive.add(otherSpent);
        ObjectNode ownSpent = receiveCase("this operation's request key spent", core, gatewayKey,
                "orders#createOrder", "createOrder", ReasonCode.REPLAY);
        ownSpent.set("spent", JsonNodeFactory.instance.arrayNode().add(RID + "|gateway|orders#createOrder|req"));
        receive.add(ownSpent);
        receive.add(receiveCase("another operation", core, gatewayKey, "orders#createOrder", "getOrder",
                ReasonCode.BINDING_MISMATCH));
        receive.add(receiveCase("no operation", core, gatewayKey, "orders#createOrder", null,
                ReasonCode.BINDING_MISMATCH));
        // The receiver supplies the bare service, so the chain's check passes and only the policy refuses: its
        // proof is for the route that names the operation.
        receive.add(receiveCase("a chain naming no operation, where the policy names them", core, gatewayKey,
                "orders", "createOrder", ReasonCode.PATH_NOT_ALLOWED));
        // Requests for items of orders' keyed operation reserve: the request key holds the key value.
        MerkleProof keyedProof = MerkleProof.parse(
                Vectors.text(rules.get("material").get("shop-keys").get("proofs").get(KEYED_ROUTE)));
        String reserveKey = RID + "|gateway|orders#reserve";
        receive.add(keyedReceiveCase("an item of a keyed operation", gatewayKey, keyedProof, KEYED_TARGET, null,
                null));
        receive.add(keyedReceiveCase("another item's request key spent", gatewayKey, keyedProof, KEYED_TARGET,
                reserveKey + "|B2|req", null));
        receive.add(keyedReceiveCase("this item's request key spent", gatewayKey, keyedProof, KEYED_TARGET,
                reserveKey + "|A1|req", ReasonCode.REPLAY));
        receive.add(keyedReceiveCase("the operation's unkeyed request key spent", gatewayKey, keyedProof,
                KEYED_TARGET, reserveKey + "|req", null));
        receive.add(keyedReceiveCase("a keyed operation with no key value", gatewayKey, keyedProof,
                "/items/%41/reserve", null, ReasonCode.BINDING_MISMATCH));
        return o;
    }

    /**
     * A request from gateway to orders whose first stamp names {@code rcv}, entered at orders under enforce with the
     * operation the framework dispatches to; the proof carried is always for {@code gateway/orders#createOrder}.
     */
    private static ObjectNode receiveCase(String name, JsonNode core, PrivateKey gatewayKey, String rcv,
            String operation, ReasonCode refusal) {
        MerkleProof proof = MerkleProof.parse(
                Vectors.text(core.get("policies").get("ops").get("proofs").get("gateway/orders#createOrder")));
        return receiveCase(name, "policy", "ops", gatewayKey, proof, "/orders", rcv, operation, refusal);
    }

    /**
     * A request from gateway to {@code orders#reserve} at {@code target}, dispatched to {@code reserve}, on
     * {@code rules.material.shop-keys} against a nonce cache holding {@code spent} (none when null).
     */
    private static ObjectNode keyedReceiveCase(String name, PrivateKey gatewayKey, MerkleProof proof, String target,
            String spent, ReasonCode refusal) {
        ObjectNode c = receiveCase(name, "material", "shop-keys", gatewayKey, proof, target, "orders#reserve",
                "reserve", refusal);
        if (spent != null) {
            c.set("spent", JsonNodeFactory.instance.arrayNode().add(spent));
        }
        return c;
    }

    /**
     * A {@code POST} of {@code target} from gateway to orders, its first stamp naming {@code rcv} and carrying
     * {@code proof}, on the policy or material ({@code source}) named {@code sourceName}.
     */
    private static ObjectNode receiveCase(String name, String source, String sourceName, PrivateKey gatewayKey,
            MerkleProof proof, String target, String rcv, String operation, ReasonCode refusal) {
        byte[] body = REQUEST_BODY;
        List<Stamp> chain = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), rcv, RequestBinding.compute("POST", target, body), List.of(), null).chain();
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put(source, sourceName);
        c.put("service", "orders");
        c.put("mode", "enforce");
        ObjectNode request = c.putObject("request");
        request.put("method", "POST");
        request.put("target", target);
        ObjectNode headers = request.putObject("headers");
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(chain));
        headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(proof));
        request.put("body", hex(body));
        if (operation == null) {
            c.putNull("operation");
        } else {
            c.put("operation", operation);
        }
        ObjectNode ring = c.putObject("keyring");
        ring.put("gateway", "gateway");
        c.putArray("allowedOrigins").add("gateway");
        c.put("sess", "");
        c.put("now", NOW);
        c.put("policyNotAfter", MESH_NOT_AFTER);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        ObjectNode e = c.putObject("expected");
        if (refusal == null) {
            e.putNull("refusal");
        } else {
            e.set("refusal", VectorsHttpRules.refusal(403, refusal));
        }
        return c;
    }

    private static void assertOperations(JsonNode o) {
        for (String name : List.of("table", "shared", "keyed")) {
            assertTable(o.get(name), name);
        }
        for (JsonNode c : o.get("refused")) {
            assertEquals("refused", c.get("expected").asText());
            assertThrows(IllegalArgumentException.class, () -> OperationTable.read(c.get("file").asText()),
                    c.get("name").asText());
        }
        for (JsonNode c : o.get("match")) {
            String got = OperationTable.read(c.get("table").asText()).match(c.get("method").asText(),
                    c.get("path").asText(), c.get("query").isNull() ? null : c.get("query").asText());
            assertEquals(c.get("expected").isNull() ? null : c.get("expected").asText(), got,
                    c.get("method").asText() + " " + c.get("path").asText() + " " + c.get("query"));
        }
        for (JsonNode c : o.get("keys")) {
            OperationTable t = OperationTable.read(c.get("table").asText());
            String path = c.get("path").asText();
            String query = c.get("query").isNull() ? null : c.get("query").asText();
            String operation = t.match(c.get("method").asText(), path, query);
            JsonNode want = c.get("expected");
            String name = "keys: " + c.get("name").asText();
            assertEquals(want.get("operation").isNull() ? null : want.get("operation").asText(), operation, name);
            assertEquals(want.get("key").isNull() ? null : want.get("key").asText(),
                    operation == null ? null : t.keyValue(operation, path, query), name);
        }
    }

    private static void assertReceive(JsonNode c, JsonNode http, JsonNode core) {
        String name = c.get("name").asText();
        HttpReceiver.Builder b = HttpReceiver.builder(c.get("service").asText()).verifyRequests(true)
                .publisher(event -> { }).verifier(verifier(c, http, core));
        if (c.has("material")) {
            b.operations(OperationTable.read(http.get("operations").get("keyed").get("file").asText()));
        }
        HttpReceiver receiver = b.build();
        JsonNode r = c.get("request");
        Map<String, String> headers = new LinkedHashMap<>();
        r.get("headers").properties().forEach(e -> headers.put(e.getKey(), e.getValue().asText()));
        InboundRequest in = new InboundRequest(r.get("method").asText(), r.get("target").asText(), headers,
                VectorsHttpRules.unhex(r.get("body")),
                c.get("operation").isNull() ? null : c.get("operation").asText());
        Accepted got = receiver.accept(in, null, VerificationMode.valueOf(c.get("mode").asText().toUpperCase()));
        JsonNode want = c.get("expected").get("refusal");
        if (want.isNull()) {
            assertEquals(null, got.refusal(), name);
        } else {
            assertEquals(want.get("status").asInt(), got.refusal().status(), name);
            assertEquals(want.get("body").asText(), hex(got.refusal().json()), name);
        }
    }

    private static String responseBinding(String resultHash, List<ContentLabel> labels) {
        return org.paztport.core.stamp.Bindings.response(resultHash, RID, labels);
    }

    private static ObjectNode responseCase(String name, List<Stamp> sent, String header, int status, byte[] body,
            int uses, long policyNotAfter, ReasonCode reason, String suspectSvc, String suspectInst,
            List<ContentLabel> labels, String resultHash) {
        return responseCase(name, "policy", "mesh", sent, "orders", null, header, status, body, uses, policyNotAfter,
                reason, suspectSvc, suspectInst, labels, resultHash);
    }

    /**
     * A responses case on the policy or material ({@code source}) named {@code sourceName}, checked by
     * {@code caller}; {@code key}, the key value of the target sent, is left out when null.
     */
    private static ObjectNode responseCase(String name, String source, String sourceName, List<Stamp> sent,
            String caller, String key, String header, int status, byte[] body, int uses, long policyNotAfter,
            ReasonCode reason, String suspectSvc, String suspectInst, List<ContentLabel> labels, String resultHash) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put(source, sourceName);
        c.set("sent", stampsJson(sent));
        c.put("caller", caller);
        if (key != null) {
            c.put("key", key);
        }
        c.put("responseHeader", header);
        c.put("status", status);
        c.put("body", hex(body));
        ObjectNode ring = c.putObject("keyring");
        ring.put("gateway", "gateway");
        ring.put("orders", "orders");
        ring.put("payment", "payment");
        c.putArray("allowedOrigins").add("gateway");
        c.put("sess", "");
        c.put("now", NOW);
        c.put("policyNotAfter", policyNotAfter);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        c.put("uses", uses);
        ObjectNode e = c.putObject("expected");
        e.put("reason", reason.name());
        e.put("suspectSvc", suspectSvc);
        e.put("suspectInst", suspectInst);
        e.set("labels", labelsJson(labels));
        e.put("resultHash", resultHash);
        return c;
    }

    private static Stamp stamp(JsonNode s) {
        return new Stamp(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
                s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), s.get("sig").asText());
    }

    /**
     * Replays every section of {@code http} through {@link HttpWire}; {@code core} supplies the shared keys and
     * policy.
     */
    static void assertAll(JsonNode http, JsonNode core) {
        for (JsonNode c : http.get("resultHash")) {
            assertEquals(c.get("hash").asText(),
                    HttpWire.resultHash(c.get("status").asInt(), HexFormat.of().parseHex(c.get("body").asText())));
        }
        for (JsonNode c : http.get("requestBinding")) {
            assertEquals(c.get("bind").asText(), RequestBinding.compute(c.get("method").asText(),
                    c.get("target").asText(), HexFormat.of().parseHex(c.get("body").asText())));
        }
        for (JsonNode c : http.get("headerNames")) {
            assertEquals(c.get("paztport").asBoolean(), PaztportHeaders.isPaztport(c.get("header").asText()),
                    "header name " + c.get("header").asText());
        }
        for (JsonNode c : http.get("responses")) {
            assertResponse(c, http, core);
        }
        assertBoundaryInfluence(http.get("boundaryInfluence"));
        assertOperations(http.get("operations"));
        for (JsonNode c : http.get("operations").get("receive")) {
            assertReceive(c, http, core);
        }
        VectorsHttpRules.assertAll(http.get("rules"), http, core);
    }

    private static PublicKey publicKey(String name, JsonNode http, JsonNode core) {
        JsonNode k = http.get("keys").has(name) ? http.get("keys").get(name) : core.get("keys").get(name);
        return Crypto.decodePublicKey(Base64Url.decode(k.get("pub").asText()));
    }

    /**
     * The root, root id and proofs a case runs on: those of the v3.json policy it names, or of the
     * {@code rules.material} it names.
     */
    private record Policy(String root, String rootId, JsonNode proofs) {

        static Policy of(JsonNode c, JsonNode http, JsonNode core) {
            if (c.has("material")) {
                JsonNode m = http.get("rules").get("material").get(c.get("material").asText());
                return new Policy(m.get("root").get("root").asText(), m.get("root").get("rootId").asText(),
                        m.get("proofs"));
            }
            JsonNode p = core.get("policies").get(c.get("policy").asText());
            return new Policy(p.get("root").asText(), p.get("rootId").asText(), p.get("proofs"));
        }
    }

    /** The verifier a case describes: one keyring and one root, each with the case's window. */
    private static Verifier verifier(JsonNode c, JsonNode http, JsonNode core) {
        Policy policy = Policy.of(c, http, core);
        Map<String, PublicKey> ring = new LinkedHashMap<>();
        c.get("keyring").properties().forEach(e -> ring.put(e.getKey(), publicKey(e.getValue().asText(), http, core)));
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        long now = c.get("now").asLong();
        long policyNotAfter = c.get("policyNotAfter").asLong();
        InMemoryNonceCache nonces = new InMemoryNonceCache(c.get("nonceTtlMs").asLong());
        if (c.has("spent")) {
            c.get("spent").forEach(k -> nonces.seenBefore(k.asText(), now));
        }
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(ring), policyNotAfter)),
                List.of(new PinnedRoot(Base64Url.decode(policy.root()), policy.rootId(), policyNotAfter)),
                policyNotAfter, origins, c.get("sess").asText(),
                nonces, () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong()));
    }

    private static void assertResponse(JsonNode c, JsonNode http, JsonNode core) {
        String name = c.get("name").asText();
        Verifier verifier = verifier(c, http, core);
        List<Stamp> sent = new ArrayList<>();
        c.get("sent").forEach(s -> sent.add(stamp(s)));
        MerkleProof proof = MerkleProof.parse(
                Vectors.text(Policy.of(c, http, core).proofs().get(c.get("proofRoute").asText())));
        JsonNode header = c.get("responseHeader");
        String key = c.has("key") ? c.get("key").asText() : null;
        HttpWire.ResponseCheck check = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            check = HttpWire.verifyResponse(verifier, sent, proof, header.isNull() ? null : header.asText(),
                    c.get("status").asInt(), HexFormat.of().parseHex(c.get("body").asText()), c.get("caller").asText(),
                    key);
        }
        JsonNode want = c.get("expected");
        assertEquals(ReasonCode.valueOf(want.get("reason").asText()), check.result().reason(), name);
        assertEquals(want.get("suspectSvc").asText(), check.result().suspectSvc(), name);
        assertEquals(want.get("suspectInst").asText(), check.result().suspectInst(), name);
        assertEquals(want.get("labels"), labelsJson(check.labels()), name);
        assertEquals(want.get("resultHash").asText(), check.resultHash(), name);
    }

    /** The exact bytes the writer puts in the file: indented JSON and a final newline. */
    static byte[] render(JsonNode built) throws IOException {
        byte[] json = MAPPER.copy().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsBytes(built);
        byte[] out = Arrays.copyOf(json, json.length + 1);
        out[json.length] = '\n';
        return out;
    }

    /** The committed file's bytes, found as {@link #load} finds it. */
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
    @EnabledIfSystemProperty(named = "paztport.exportHttpVectors", matches = "true")
    void export() throws IOException {
        Path file = Path.of(System.getProperty("vectors.out", "target/http-v3.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, render(build()));
    }
}
