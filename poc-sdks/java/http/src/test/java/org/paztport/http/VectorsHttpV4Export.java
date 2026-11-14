// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
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
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

/**
 * Builds {@code spec/vectors/http-v4.json} and replays it. It is deterministic: the clock, rid and timestamps are
 * fixed, the one new key is derived by {@code v4.json}'s rule, and Ed25519 signs deterministically, so {@link #build}
 * reproduces the committed bytes and {@code VectorsHttpV4Test} pins them. The writer is opt-in. This class is not
 * matched by Surefire's default includes, so name it: {@code (cd poc-sdks/java && mvn -q -pl core,http test
 * -Dtest=VectorsHttpV4Export -Dpaztport.exportHttpVectors=true -Dvectors.out=<repo>/poc-sdks/spec/vectors/http-v4.json
 * -Dsurefire.failIfNoSpecifiedTests=false)}. {@link #build} replays every case it records, so an export can never
 * record a wrong answer.
 */
class VectorsHttpV4Export {

    private static final String ABOUT = "Paztport version 4 over HTTP: conformance vectors. The keys, the `mesh` and"
            + " `ops` policies and their proofs are the ones in v4.json, by name; only the `payment` key is new,"
            + " derived by v4.json's rule (seed = SHA-256(utf8(\"paztport-v3-vector-key:payment\")), the same PKCS#8"
            + " and SPKI encodings, both base64url), and the boundary key below is"
            + " SHA-256(utf8(\"paztport-http-v3-vector-boundary-key\")), base64url. The v3 in these seed strings,"
            + " and in those `rules.about` gives, is historical: they are http-v3.json's, kept so that the keys,"
            + " boundaryInfluence, and the keys, material, handshakes and peers of `rules`, are http-v3.json's value"
            + " for value. resultHash, requestBinding, and operations but for `receive`, are too, since their rules"
            + " did not change, and headerNames holds each of http-v3.json's cases. resultHash maps a status and body"
            + " (hex) to the result hash. requestBinding maps a method, a target (the raw path plus `?` and the raw"
            + " query when there is one) and a body (hex) to the request binding. headerNames maps a header name to"
            + " whether it is Paztport's: it begins with `X-Path-`, compared case-insensitively over ASCII. A"
            + " responses case is a request chain `sent` from gateway to orders to payment, with the blocks"
            + " `sentBlocks` sent beside it, one per stamp, and the `responseHeader` payment returned; the caller"
            + " `orders` checks it against `status` and `body` (hex) with the proof that the v4.json `policy` it"
            + " names holds for `proofRoute`, as a verifier that acts on the extensions in `actsOn` and carries the"
            + " names in `allowedExtensions` (null for unset, which carries any name), whose policy window ends at"
            + " `policyNotAfter` and whose clock reads `now`, running the check `uses` times against one nonce cache"
            + " of nonceTtlMs that already holds `spent` (none when absent), each nonce key the JCS text of its array"
            + " of strings. It expects the last result, {reason, suspectSvc, suspectInst, handOver, resultHash}:"
            + " handOver is null unless the reason is OK, and then has one member per name in actsOn, each an array"
            + " of {svc, items}, one per stamp of the sent chain and then the response stamp, items null where the"
            + " stamp's block does not name the extension, as v4.json's verify cases record it. The responses cases"
            + " on the `ops` policy run on a chain that names the operation each hop invokes (`orders#createOrder`,"
            + " then `payment#charge`), with the proof for that route. The last three name `material` in place of"
            + " `policy` and run on `rules.material.shop-keys`: each is a chain `sent` from gateway to orders naming"
            + " `orders#reserve` and the `responseHeader` orders returned, which the caller `gateway` checks with"
            + " `key`, the key value of the target sent. boundaryInfluence is the influence an egress sends to"
            + " another organisation: under the boundary `key`, for `rid`, the partner entry `rcv` and the `egress`,"
            + " the `input` entries reduce to `reduced`, with one salt (base64url) per (cls, owner) group in"
            + " `salts`; each `openings` case is a `sent` entry and an `opening`, with its JCS bytes in `body`"
            + " (hex), which the replay reads, and `opens` says whether it opens. `operations` holds `table`, an"
            + " operation table as a `file` (its text) and `value`, with its `opsHash` and the `route` a root covers"
            + " it as; `shared`, payment's table, an entrance with two operations told apart by a query condition,"
            + " in the same form; `keyed`, a table whose operations declare keys, in the same form; `refused`, table"
            + " files a reader refuses; `match`, a method, a raw path and a raw query (null for none) against a"
            + " table `file` and the operation name it gives, null for none; `keys`, cases giving a call's operation"
            + " in `keyed` and its key value, null for none; and `receive`, a request entered at `orders` through"
            + " the HTTP receiver under enforce, on the v4.json `policy` or the `rules.material` it names, against a"
            + " nonce cache that already holds `spent` (none when absent), whose chain's first stamp names `orders`"
            + " or an operation of it, its `X-Path-Extensions` one empty block per stamp, with the `operation` the"
            + " framework dispatches to (null for none), the receiver's `actsOn` and `allowedExtensions` as above,"
            + " and the `refusal` it expects (null when the request is served). Every `receive` case on the `ops`"
            + " policy carries the proof of `gateway/orders#createOrder`, whatever its chain names; those naming"
            + " `material` carry its proof of `gateway/orders#reserve`, and the receiver holds `keyed` as its own"
            + " table. `rules` holds the HTTP rules a receiver, a caller, a partner and an egress follow, and its"
            + " `about` says how its cases read. Ed25519 is deterministic, so the file is reproduced byte for byte."
            + " Java writes and replays this file; Go replays http-v3.json until it moves; the TypeScript SDK has no"
            + " HTTP binding, so it does not replay it.";

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
    private static final String OPS_ROUTE = "gateway/orders#createOrder/payment#charge";
    private static final byte[] REQUEST_BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_BODY = "{\"paid\":true}".getBytes(StandardCharsets.UTF_8);
    private static final String KEY_PREFIX = "302e020100300506032b657004220420";
    private static final byte[] BOUNDARY_KEY =
            Crypto.sha256("paztport-http-v3-vector-boundary-key".getBytes(StandardCharsets.UTF_8));
    private static final String PARTNER_ENTRY = "psp";
    private static final String EGRESS = "payment";
    private static final String KEYED_TARGET = "/items/A1/reserve";

    /** A caller that acts on influence and carries any name. */
    private static final ExtensionSettings ACTS_ON_INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);
    /** The label payment's labelled responses carry. */
    private static final ContentLabel RECEIPT = new ContentLabel(InfluenceClass.PRIVATE, "cid-receipt-1", "alice");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A committed vector file, read by core's loader so each value reaches the SDK as the file writes it. */
    static JsonNode load(String name) throws IOException {
        return Vectors.load(name);
    }

    /** The key v4.json's rule gives {@code name}: the seed is a hash of the name, the public key follows from it. */
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

    // --- JSON ---

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    static byte[] unhex(JsonNode n) {
        return HexFormat.of().parseHex(n.asText());
    }

    /**
     * A value the SDK wrote as JSON text, as a tree to place in a vector, each object's members in the order the
     * vectors list them.
     */
    static JsonNode tree(String json) {
        try {
            return layout(MAPPER.readTree(json));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A kind of object, told by the members it always has, and the order a vector lists its members in. */
    private record Layout(Set<String> marker, List<String> order) {
    }

    private static final List<Layout> LAYOUTS = List.of(
            new Layout(Set.of("v", "svc", "rcv"),
                    List.of("v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "ext", "prev", "sig")),
            new Layout(Set.of("leafSalt"), List.of("leafSalt", "siblings", "dirs", "rootId")),
            new Layout(Set.of("root", "rootId"), List.of("rootId", "root", "sig", "notAfter")),
            new Layout(Set.of("services", "policy"), List.of("services", "policy", "sig", "notAfter")),
            new Layout(Set.of("policy", "svc", "key"), List.of("policy", "svc", "key", "notAfter", "sig")),
            new Layout(Set.of("cls", "src", "h"), List.of("cls", "src", "h", "cid", "owner")),
            new Layout(Set.of("cls", "cid"), List.of("cls", "cid", "owner")),
            new Layout(Set.of("cls", "salt", "originals"), List.of("cls", "owner", "salt", "originals")),
            new Layout(Set.of("clientPolicyKey"), List.of("clientRoot", "clientPolicyKey", "clientKeyring",
                    "clientKeyringSig", "clientKeyringNotAfter", "nonce")));

    /** {@code n} with the members of every object in the order its kind's layout gives; other objects keep theirs. */
    private static JsonNode layout(JsonNode n) {
        if (n.isArray()) {
            ArrayNode a = JsonNodeFactory.instance.arrayNode();
            n.forEach(item -> a.add(layout(item)));
            return a;
        } else if (!n.isObject()) {
            return n;
        }
        List<String> names = new ArrayList<>();
        n.fieldNames().forEachRemaining(names::add);
        List<String> order = LAYOUTS.stream()
                .filter(l -> names.containsAll(l.marker()) && l.order().containsAll(names))
                .map(Layout::order).findFirst().orElse(names);
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        for (String name : order) {
            if (n.has(name)) {
                o.set(name, layout(n.get(name)));
            }
        }
        return o;
    }

    /** A refusal: the status and exactly {@code {"reason":"<code>"}}, with no whitespace and no other member. */
    static ObjectNode refusal(int status, ReasonCode reason) {
        ObjectNode r = JsonNodeFactory.instance.objectNode();
        r.put("status", status);
        r.put("body", hex(("{\"reason\":\"" + reason.name() + "\"}").getBytes(StandardCharsets.UTF_8)));
        return r;
    }

    /**
     * A nonce key as the spec writes it, the JCS text of its array of strings, written out here rather than by the
     * SDK, so a spent key pins the SDK's own. Every part the vectors use is plain ASCII with no character JCS
     * escapes.
     */
    static String nonceKey(String... parts) {
        return "[\"" + String.join("\",\"", parts) + "\"]";
    }

    private static ArrayNode stampsJson(List<Stamp> stamps) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        stamps.forEach(s -> a.add(tree(s.toJson())));
        return a;
    }

    private static ArrayNode blocksJson(List<Block> blocks) {
        return (ArrayNode) tree(Block.toJson(blocks));
    }

    static ArrayNode entriesJson(List<InfluenceEntry> entries) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        entries.forEach(e -> a.add(tree(e.toJson())));
        return a;
    }

    static List<InfluenceEntry> entries(JsonNode n) {
        List<InfluenceEntry> out = new ArrayList<>();
        n.forEach(e -> out.add(InfluenceEntry.parse(Vectors.text(e))));
        return out;
    }

    /**
     * A hand-over as the vectors record it, as v4.json's verify cases do: null, or one member per name acted on,
     * each an array of {@code {svc, items}}, one per stamp, items null where the block does not name it.
     */
    static JsonNode handOverJson(HandOver h) {
        if (h == null) {
            return JsonNodeFactory.instance.nullNode();
        }
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        for (String name : h.names()) {
            ArrayNode stamps = o.putArray(name);
            for (HandOver.StampItems s : h.under(name)) {
                ObjectNode entry = stamps.addObject();
                entry.put("svc", s.svc());
                if (s.items() == null) {
                    entry.putNull("items");
                } else {
                    ArrayNode items = entry.putArray("items");
                    s.items().forEach(item -> items.add(tree(item)));
                }
            }
        }
        return o;
    }

    private static ArrayNode names(Set<String> names) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        names.stream().sorted().forEach(a::add);
        return a;
    }

    /** Puts {@code actsOn} and {@code allowedExtensions} (null for unset) on a case. */
    static void putSettings(ObjectNode c, ExtensionSettings settings) {
        c.set("actsOn", names(settings.actsOn()));
        if (settings.allowed() == null) {
            c.putNull("allowedExtensions");
        } else {
            c.set("allowedExtensions", names(settings.allowed()));
        }
    }

    /** A case's extension settings: its {@code actsOn}, and its {@code allowedExtensions}, null for unset. */
    static ExtensionSettings settings(JsonNode c) {
        JsonNode allowed = c.get("allowedExtensions");
        return ExtensionSettings.of(textSet(c.get("actsOn")), allowed.isNull() ? null : textSet(allowed));
    }

    private static Set<String> textSet(JsonNode array) {
        Set<String> out = new LinkedHashSet<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    // --- The file ---

    static ObjectNode build() throws IOException {
        JsonNode core = load("v4.json");
        KeyPair payment = derive("payment");
        PrivateKey gatewayKey =
                Crypto.decodePrivateKey(Base64Url.decode(core.get("keys").get("gateway").get("priv").asText()));
        PrivateKey ordersKey =
                Crypto.decodePrivateKey(Base64Url.decode(core.get("keys").get("orders").get("priv").asText()));

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

        // X-Path-Influence, version 3's header, stays: it is Paztport's by its prefix, as any name added later is.
        ArrayNode headerNames = out.putArray("headerNames");
        for (String name : new String[] {"X-Path-Chain", "x-path-chain", "X-PATH-PROOF", "X-Path-Extensions",
                "X-Path-Influence", "X-Path-Session", "X-Path-Response", "X-Path-Future", "X-Path-", "X-Path",
                "X-Pathology", "X-Path_Chain", "XX-Path-Chain", "", "X\u2010Path\u2010Chain", "X-P\u0430th-Chain"}) {
            ObjectNode o = headerNames.addObject();
            o.put("header", name);
            o.put("paztport", PaztportHeaders.isPaztport(name));
        }

        ArrayNode responses = out.putArray("responses");
        responses(gatewayKey, ordersKey, payment).forEach(responses::add);
        operationsResponses(gatewayKey, ordersKey, payment).forEach(responses::add);
        keyedResponses(gatewayKey, ordersKey).forEach(responses::add);

        // In http-v3.json's place, before the sections after it: the keyed receive cases read its material.
        out.set("rules", VectorsHttpRules.build(out, core));
        out.set("boundaryInfluence", boundaryInfluence());
        out.set("operations", operations(core, out.get("rules"), gatewayKey));

        // Replay what was just built, read back from the text it is written as, so an export can never record a
        // wrong answer.
        assertAll(Vectors.read(new String(render(out), StandardCharsets.UTF_8)), core);
        return out;
    }

    // --- responses ---

    /** A chain a caller sent and the blocks it sent beside it, one per stamp. */
    private record Sent(List<Stamp> chain, List<Block> blocks) {
    }

    /**
     * The responses on the route {@code gateway/orders/payment}: the chain gateway to orders to payment, exactly as
     * Stamper builds it in a mesh, with every hop's block empty, and payment's answers to it. Payment acts on
     * influence, so its block names influence: with no label, with a label, which then requires influence of its
     * caller, or with no label but requiring influence all the same.
     */
    private static List<ObjectNode> responses(PrivateKey gatewayKey, PrivateKey ordersKey, KeyPair payment) {
        Stamper.Stamped toOrders = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders", "bind-gateway-to-orders", Block.EMPTY, null);
        Stamper.Stamped toPayment = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> ORDERS_TS)
                .next(toOrders.chain(), "payment", RequestBinding.compute("POST", "/pay", REQUEST_BODY), Block.EMPTY,
                        null);
        Sent sent = new Sent(toPayment.chain(), List.of(Block.EMPTY, Block.EMPTY));
        Stamper responder = new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> RID, () -> RESPONSE_TS);
        String okHash = HttpWire.resultHash(200, RESPONSE_BODY);

        Block unlabelled = ContentLabel.block(List.of(), List.of());
        Stamp okStamp = responder.respond(sent.chain(), okHash, RID, unlabelled);
        String okHeader = HttpWire.encodeResponse(okStamp, unlabelled);
        // A properly signed response, but to the gateway rather than to the caller that sent the request.
        Stamp toGateway = Stamp.sign("payment", "pay-1", RID, RESPONSE_TS, "", "gateway",
                Bindings.response(okHash, RID), unlabelled.commit(), sent.chain().get(sent.chain().size() - 1).sig(),
                payment.getPrivate());
        Block labelled = ContentLabel.block(List.of(RECEIPT), List.of());
        Stamp labelledStamp = responder.respond(sent.chain(), okHash, RID, labelled);
        // The receipt made public, its owner dropped: a block neither stamp committed to, put in place of the
        // unlabelled response's block (a label added) and of the labelled response's (a label downgraded).
        Block publicReceipt = ContentLabel.block(
                List.of(new ContentLabel(InfluenceClass.PUBLIC, RECEIPT.cid(), null)), List.of());
        Block requiring = ContentLabel.block(List.of(), List.of(Influence.NAME));
        Stamp requiringStamp = responder.respond(sent.chain(), okHash, RID, requiring);
        String requiringHeader = HttpWire.encodeResponse(requiringStamp, requiring);

        List<ObjectNode> cases = new ArrayList<>();
        cases.add(ok(responseCase("response ok", sent, okHeader, ACTS_ON_INFLUENCE), sent, okStamp, unlabelled,
                okHash));
        cases.add(refused(responseCase("response to wrong receiver", sent,
                HttpWire.encodeResponse(toGateway, unlabelled), ACTS_ON_INFLUENCE), ReasonCode.BINDING_MISMATCH,
                okHash));
        cases.add(refused(responseCase("labels altered", sent, HttpWire.encodeResponse(okStamp, publicReceipt),
                ACTS_ON_INFLUENCE), ReasonCode.EXTENSION_MISMATCH, okHash));
        ObjectNode status = responseCase("status altered", sent, okHeader, ACTS_ON_INFLUENCE);
        status.put("status", 500);
        cases.add(refused(status, ReasonCode.BINDING_MISMATCH, HttpWire.resultHash(500, RESPONSE_BODY)));
        ObjectNode replayed = responseCase("replayed response", sent, okHeader, ACTS_ON_INFLUENCE);
        replayed.put("uses", 2);
        cases.add(refused(replayed, ReasonCode.REPLAY, okHash));
        ObjectNode expired = responseCase("policy expired", sent, okHeader, ACTS_ON_INFLUENCE);
        expired.put("policyNotAfter", NOW - 1);
        cases.add(refused(expired, ReasonCode.POLICY_EXPIRED, okHash));

        cases.add(ok(responseCase("a block naming influence with a label", sent,
                HttpWire.encodeResponse(labelledStamp, labelled), ACTS_ON_INFLUENCE), sent, labelledStamp, labelled,
                okHash));
        cases.add(refused(responseCase("a labelled block altered", sent,
                HttpWire.encodeResponse(labelledStamp, publicReceipt), ACTS_ON_INFLUENCE),
                ReasonCode.EXTENSION_MISMATCH, okHash));
        cases.add(refused(responseCase("a header without block", sent,
                token("{\"stamp\":" + okStamp.toJson() + "}"), ACTS_ON_INFLUENCE), ReasonCode.CHAIN_MISSING, okHash));
        cases.add(refused(responseCase("a header in version 3's labels and stamp shape", sent,
                token("{\"labels\":[" + RECEIPT.toJson() + "],\"stamp\":" + labelledStamp.toJson() + "}"),
                ACTS_ON_INFLUENCE), ReasonCode.CHAIN_MISSING, okHash));
        // The labelled response's own header, JCS and all, with one member past the two it may have.
        cases.add(refused(responseCase("a header with a member beside block and stamp", sent,
                token("{\"block\":" + labelled.toJson() + ",\"labels\":[" + RECEIPT.toJson() + "],\"stamp\":"
                        + labelledStamp.toJson() + "}"), ACTS_ON_INFLUENCE), ReasonCode.CHAIN_MISSING, okHash));
        cases.add(refused(responseCase("a last block requiring influence at a caller that does not act on it", sent,
                requiringHeader, ExtensionSettings.NONE), ReasonCode.EXTENSION_REQUIRED, okHash));
        cases.add(ok(responseCase("a last block requiring influence at a caller that acts on it", sent,
                requiringHeader, ACTS_ON_INFLUENCE), sent, requiringStamp, requiring, okHash));
        cases.forEach(c -> c.put("proofRoute", ROUTE));
        return cases;
    }

    /** The base64url of JCS text, as every header carries a value. */
    private static String token(String jcsText) {
        return Base64Url.encode(jcsText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Responses on the route through operations: payment's response stamp names {@code orders}, the caller. The
     * response's nonce key names the operation the sent chain invokes, so another operation's spent key does not
     * refuse it and its own does.
     */
    private static List<ObjectNode> operationsResponses(PrivateKey gatewayKey, PrivateKey ordersKey,
            KeyPair payment) {
        Stamper.Stamped toOrders = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders#createOrder", "bind-gateway-to-orders", Block.EMPTY, null);
        Stamper.Stamped toPayment = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> ORDERS_TS)
                .next(toOrders.chain(), "payment#charge", RequestBinding.compute("POST", "/pay", REQUEST_BODY),
                        Block.EMPTY, null);
        Sent sent = new Sent(toPayment.chain(), List.of(Block.EMPTY, Block.EMPTY));
        String okHash = HttpWire.resultHash(200, RESPONSE_BODY);
        Block unlabelled = ContentLabel.block(List.of(), List.of());
        Stamp ok = new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> RID, () -> RESPONSE_TS)
                .respond(sent.chain(), okHash, RID, unlabelled);
        String header = HttpWire.encodeResponse(ok, unlabelled);
        ObjectNode c = ok(responseCase("a response on a route through operations", sent, header,
                ACTS_ON_INFLUENCE), sent, ok, unlabelled, okHash);
        ObjectNode other = ok(responseCase("another operation's response key spent", sent, header,
                ACTS_ON_INFLUENCE), sent, ok, unlabelled, okHash);
        other.set("spent", JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "payment#refund", "resp")));
        ObjectNode own = refused(responseCase("this operation's response key spent", sent, header,
                ACTS_ON_INFLUENCE), ReasonCode.REPLAY, okHash);
        own.set("spent", JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "payment#charge", "resp")));
        List<ObjectNode> cases = List.of(c, other, own);
        cases.forEach(o -> {
            o.put("policy", "ops");
            o.put("proofRoute", OPS_ROUTE);
        });
        return cases;
    }

    /** The route through orders' keyed operation {@code reserve}, which {@code rules.material.shop-keys} covers. */
    static final String KEYED_ROUTE = "gateway/orders#reserve";

    /**
     * Responses from the item {@code A1} of orders' keyed operation {@code reserve} to the gateway, on
     * {@code rules.material.shop-keys}. The response's nonce key holds the key value of the target sent, so another
     * item's spent key does not refuse it and its own does. orders acts on influence and labels its answer.
     */
    private static List<ObjectNode> keyedResponses(PrivateKey gatewayKey, PrivateKey ordersKey) {
        List<Stamp> chain = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders#reserve", RequestBinding.compute("POST", KEYED_TARGET, REQUEST_BODY),
                        Block.EMPTY, null).chain();
        Sent sent = new Sent(chain, List.of(Block.EMPTY));
        String okHash = HttpWire.resultHash(200, RESPONSE_BODY);
        Block labelled = ContentLabel.block(List.of(RECEIPT), List.of());
        Stamp ok = new Stamper("orders", "ord-1", ordersKey, false, () -> RID, () -> RESPONSE_TS)
                .respond(chain, okHash, RID, labelled);
        String header = HttpWire.encodeResponse(ok, labelled);
        ObjectNode c = ok(keyedResponse("a response from an item of a keyed operation", sent, header), sent, ok,
                labelled, okHash);
        ObjectNode other = ok(keyedResponse("another item's response key spent", sent, header), sent, ok, labelled,
                okHash);
        other.set("spent", JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "orders#reserve", "B2", "resp")));
        ObjectNode own = refused(keyedResponse("this item's response key spent", sent, header), ReasonCode.REPLAY,
                okHash);
        own.set("spent", JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "orders#reserve", "A1", "resp")));
        List<ObjectNode> cases = List.of(c, other, own);
        cases.forEach(o -> o.put("proofRoute", KEYED_ROUTE));
        return cases;
    }

    private static ObjectNode keyedResponse(String name, Sent sent, String header) {
        return responseCase(name, "material", "shop-keys", sent, "gateway", "A1", header, ACTS_ON_INFLUENCE);
    }

    private static ObjectNode responseCase(String name, Sent sent, String header, ExtensionSettings settings) {
        return responseCase(name, "policy", "mesh", sent, "orders", null, header, settings);
    }

    /**
     * A responses case on the v4.json policy or the {@code rules.material} ({@code source}) named {@code sourceName},
     * checked by {@code caller} under {@code settings}, with {@code key}, the key value of the target sent, left out
     * when null: status 200 with the responder's body, one use, and the window {@link #MESH_NOT_AFTER}; a case
     * changes what it varies in place.
     */
    private static ObjectNode responseCase(String name, String source, String sourceName, Sent sent, String caller,
            String key, String header, ExtensionSettings settings) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put(source, sourceName);
        c.set("sent", stampsJson(sent.chain()));
        c.set("sentBlocks", blocksJson(sent.blocks()));
        c.put("caller", caller);
        if (key != null) {
            c.put("key", key);
        }
        c.put("responseHeader", header);
        c.put("status", 200);
        c.put("body", hex(RESPONSE_BODY));
        ObjectNode ring = c.putObject("keyring");
        ring.put("gateway", "gateway");
        ring.put("orders", "orders");
        ring.put("payment", "payment");
        c.putArray("allowedOrigins").add("gateway");
        c.put("sess", "");
        putSettings(c, settings);
        c.put("now", NOW);
        c.put("policyNotAfter", MESH_NOT_AFTER);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        c.put("uses", 1);
        return c;
    }

    /**
     * Expects OK, the response's signer as suspect, and the hand-over the caller's settings give over the chain sent
     * then {@code response}, with the blocks sent then {@code block}.
     */
    private static ObjectNode ok(ObjectNode c, Sent sent, Stamp response, Block block, String resultHash) {
        List<Stamp> stamps = new ArrayList<>(sent.chain());
        stamps.add(response);
        List<Block> blocks = new ArrayList<>(sent.blocks());
        blocks.add(block);
        return expect(c, ReasonCode.OK, response.svc(), response.inst(),
                new HandOver(true, stamps, blocks, settings(c)), resultHash);
    }

    /** Expects {@code reason}, which names no suspect without a peer, and nothing handed over. */
    private static ObjectNode refused(ObjectNode c, ReasonCode reason, String resultHash) {
        return expect(c, reason, "", "", null, resultHash);
    }

    private static ObjectNode expect(ObjectNode c, ReasonCode reason, String suspectSvc, String suspectInst,
            HandOver handOver, String resultHash) {
        ObjectNode e = c.putObject("expected");
        e.put("reason", reason.name());
        e.put("suspectSvc", suspectSvc);
        e.put("suspectInst", suspectInst);
        e.set("handOver", handOverJson(handOver));
        e.put("resultHash", resultHash);
        return c;
    }

    private static void assertResponse(JsonNode c, JsonNode http, JsonNode core) {
        String name = c.get("name").asText();
        Verifier verifier = verifier(c, http, core);
        ParsedChain parsed = Chains.parse(Vectors.text(c.get("sent")));
        assertTrue(parsed.ok(), name + ": the sent chain reads");
        List<Block> sentBlocks = Block.parseAll(Vectors.text(c.get("sentBlocks")));
        MerkleProof proof = MerkleProof.parse(
                Vectors.text(Policy.of(c, http, core).proofs().get(c.get("proofRoute").asText())));
        JsonNode header = c.get("responseHeader");
        String key = c.has("key") ? c.get("key").asText() : null;
        HttpWire.ResponseCheck check = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            check = HttpWire.verifyResponse(verifier, parsed.stamps(), sentBlocks, proof,
                    header.isNull() ? null : header.asText(), c.get("status").asInt(), unhex(c.get("body")),
                    c.get("caller").asText(), key);
        }
        JsonNode want = c.get("expected");
        assertEquals(ReasonCode.valueOf(want.get("reason").asText()), check.result().reason(), name);
        assertEquals(want.get("suspectSvc").asText(), check.result().suspectSvc(), name);
        assertEquals(want.get("suspectInst").asText(), check.result().suspectInst(), name);
        assertEquals(want.get("handOver"), handOverJson(check.result().handOver()), name);
        assertEquals(want.get("resultHash").asText(), check.resultHash(), name);
    }

    // --- boundaryInfluence ---

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
        b.set("input", entriesJson(input));
        ArrayNode salts = b.putArray("salts");
        for (InfluenceEntry e : reduced) {
            ObjectNode s = salts.addObject();
            s.put("cls", e.cls().wire());
            if (e.owner() != null) {
                s.put("owner", e.owner());
            }
            s.put("salt", boundarySalt(e));
        }
        b.set("reduced", entriesJson(reduced));
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
        c.put("body", hex(opening.getBytes(StandardCharsets.UTF_8)));
        c.put("opens", opens);
        return c;
    }

    private static void assertBoundaryInfluence(JsonNode b) {
        byte[] key = Base64Url.decode(b.get("key").asText());
        String rid = b.get("rid").asText();
        String rcv = b.get("rcv").asText();
        List<InfluenceEntry> reduced = BoundaryInfluence.reduce(entries(b.get("input")), key, rid, rcv,
                b.get("egress").asText());
        assertEquals(b.get("reduced"), entriesJson(reduced), "boundary reduced");
        assertEquals(b.get("salts").size(), reduced.size(), "a salt per group");
        for (JsonNode s : b.get("salts")) {
            InfluenceClass cls = InfluenceClass.fromWire(s.get("cls").asText());
            String owner = s.has("owner") ? s.get("owner").asText() : null;
            assertEquals(s.get("salt").asText(), Base64Url.encode(BoundaryInfluence.salt(key, rid, rcv, cls, owner)),
                    "boundary salt " + s);
        }
        for (JsonNode c : b.get("openings")) {
            InfluenceEntry sent = InfluenceEntry.parse(Vectors.text(c.get("sent")));
            BoundaryInfluence.Opening opening = BoundaryInfluence.Opening.parse(unhex(c.get("body")));
            assertEquals(c.get("opening"), tree(opening.toJson()), "opening body " + c.get("name").asText());
            assertEquals(c.get("opens").asBoolean(), BoundaryInfluence.opens(sent, opening), c.get("name").asText());
        }
    }

    // --- operations ---

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

        MerkleProof proof = MerkleProof.parse(
                Vectors.text(core.get("policies").get("ops").get("proofs").get("gateway/orders#createOrder")));
        ArrayNode receive = o.putArray("receive");
        receive.add(receiveCase("the operation the chain names", gatewayKey, proof, "orders#createOrder",
                "createOrder", null));
        ObjectNode otherSpent = receiveCase("another operation's request key spent", gatewayKey, proof,
                "orders#createOrder", "createOrder", null);
        otherSpent.set("spent",
                JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "gateway", "orders#getOrder", "req")));
        receive.add(otherSpent);
        ObjectNode ownSpent = receiveCase("this operation's request key spent", gatewayKey, proof,
                "orders#createOrder", "createOrder", ReasonCode.REPLAY);
        ownSpent.set("spent",
                JsonNodeFactory.instance.arrayNode().add(nonceKey(RID, "gateway", "orders#createOrder", "req")));
        receive.add(ownSpent);
        receive.add(receiveCase("another operation", gatewayKey, proof, "orders#createOrder", "getOrder",
                ReasonCode.BINDING_MISMATCH));
        receive.add(receiveCase("no operation", gatewayKey, proof, "orders#createOrder", null,
                ReasonCode.BINDING_MISMATCH));
        // The receiver supplies the bare service, so the chain's check passes and only the policy refuses: its
        // proof is for the route that names the operation.
        receive.add(receiveCase("a chain naming no operation, where the policy names them", gatewayKey, proof,
                "orders", "createOrder", ReasonCode.PATH_NOT_ALLOWED));
        // Requests for items of orders' keyed operation reserve: the request key holds the key value.
        MerkleProof keyedProof = MerkleProof.parse(
                Vectors.text(rules.get("material").get("shop-keys").get("proofs").get(KEYED_ROUTE)));
        receive.add(keyedReceiveCase("an item of a keyed operation", gatewayKey, keyedProof, KEYED_TARGET, null,
                null));
        receive.add(keyedReceiveCase("another item's request key spent", gatewayKey, keyedProof, KEYED_TARGET,
                nonceKey(RID, "gateway", "orders#reserve", "B2", "req"), null));
        receive.add(keyedReceiveCase("this item's request key spent", gatewayKey, keyedProof, KEYED_TARGET,
                nonceKey(RID, "gateway", "orders#reserve", "A1", "req"), ReasonCode.REPLAY));
        receive.add(keyedReceiveCase("the operation's unkeyed request key spent", gatewayKey, keyedProof,
                KEYED_TARGET, nonceKey(RID, "gateway", "orders#reserve", "req"), null));
        receive.add(keyedReceiveCase("a keyed operation with no key value", gatewayKey, keyedProof,
                "/items/%41/reserve", null, ReasonCode.BINDING_MISMATCH));
        return o;
    }

    /**
     * A {@code POST /orders} from gateway to orders on the {@code ops} policy, its first stamp naming {@code rcv},
     * and carrying {@code proof}, entered at orders with the operation the framework dispatches to.
     */
    private static ObjectNode receiveCase(String name, PrivateKey gatewayKey, MerkleProof proof, String rcv,
            String operation, ReasonCode refusal) {
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
     * A {@code POST} of {@code target} from gateway to orders on the v4.json policy or the {@code rules.material}
     * ({@code source}) named {@code sourceName}, its first stamp naming {@code rcv}, its block empty, and carrying
     * {@code proof}, entered at orders under enforce with the operation the framework dispatches to.
     */
    private static ObjectNode receiveCase(String name, String source, String sourceName, PrivateKey gatewayKey,
            MerkleProof proof, String target, String rcv, String operation, ReasonCode refusal) {
        byte[] body = REQUEST_BODY;
        List<Stamp> chain = new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), rcv, RequestBinding.compute("POST", target, body), Block.EMPTY, null).chain();
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
        headers.put(PaztportHeaders.EXTENSIONS, HttpWire.encodeBlocks(List.of(Block.EMPTY)));
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
        putSettings(c, ExtensionSettings.NONE);
        c.put("now", NOW);
        c.put("policyNotAfter", MESH_NOT_AFTER);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        ObjectNode e = c.putObject("expected");
        if (refusal == null) {
            e.putNull("refusal");
        } else {
            e.set("refusal", refusal(403, refusal));
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
                unhex(r.get("body")), c.get("operation").isNull() ? null : c.get("operation").asText());
        Accepted got = receiver.accept(in, null, VerificationMode.valueOf(c.get("mode").asText().toUpperCase()));
        JsonNode want = c.get("expected").get("refusal");
        if (want.isNull()) {
            assertEquals(null, got.refusal(), name);
        } else {
            assertEquals(want.get("status").asInt(), got.refusal().status(), name);
            assertEquals(want.get("body").asText(), hex(got.refusal().json()), name);
        }
    }

    // --- The replay ---

    /**
     * Replays every section of {@code http} through {@link HttpWire} and the HTTP receiver; {@code core} supplies the
     * shared keys and policies.
     */
    static void assertAll(JsonNode http, JsonNode core) {
        for (JsonNode c : http.get("resultHash")) {
            assertEquals(c.get("hash").asText(), HttpWire.resultHash(c.get("status").asInt(), unhex(c.get("body"))));
        }
        for (JsonNode c : http.get("requestBinding")) {
            assertEquals(c.get("bind").asText(), RequestBinding.compute(c.get("method").asText(),
                    c.get("target").asText(), unhex(c.get("body"))));
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
     * The root, root id and proofs a case runs on: those of the v4.json policy it names, or of the
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

    /**
     * The verifier a case describes: one keyring and the root it runs on ({@link Policy}), each with the case's
     * window, and the case's extension settings.
     */
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
                policyNotAfter, origins, c.get("sess").asText(), nonces, () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong(), settings(c)));
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
        Path file = Path.of(System.getProperty("vectors.out", "target/http-v4.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, render(build()));
    }
}
