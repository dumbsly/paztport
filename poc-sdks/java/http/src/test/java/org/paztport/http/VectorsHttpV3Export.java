// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
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
            + " case-insensitively over ASCII. A responses case is a request chain `sent` from gateway to orders to payment and the"
            + " `responseHeader` payment returned; the caller `orders` checks it against `status` and `body` (hex)"
            + " with the proof the mesh policy holds for `proofRoute`, as a verifier whose policy window ends at"
            + " `policyNotAfter` and whose clock reads `now`, running the check `uses` times against one"
            + " nonce cache of nonceTtlMs, and expects the last result, with `labels` empty unless the reason is OK."
            + " boundaryInfluence is the influence an egress sends to another organisation: under the boundary `key`"
            + " (SHA-256(utf8(\"paztport-http-v3-vector-boundary-key\")), base64url), for `rid`, the partner entry"
            + " `rcv` and the `egress`, the `input` entries reduce to `reduced`, with one salt (base64url) per"
            + " (cls, owner) group in `salts`; each `openings` case is a `sent` entry and an `opening`, with its"
            + " JCS bytes in `body` (hex), which the replay reads, and `opens` says whether it opens. Ed25519 is"
            + " deterministic, so the file is reproduced byte for byte. Java writes and replays this"
            + " file and Go replays it; the TypeScript SDK does not speak v3 over HTTP, so it does not replay it.";

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
        out.set("rules", VectorsHttpRules.build(out, core));

        out.set("boundaryInfluence", boundaryInfluence());

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

    private static String responseBinding(String resultHash, List<ContentLabel> labels) {
        return org.paztport.core.stamp.Bindings.response(resultHash, RID, labels);
    }

    private static ObjectNode responseCase(String name, List<Stamp> sent, String header, int status, byte[] body,
            int uses, long policyNotAfter, ReasonCode reason, String suspectSvc, String suspectInst,
            List<ContentLabel> labels, String resultHash) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put("policy", "mesh");
        c.set("sent", stampsJson(sent));
        c.put("caller", "orders");
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
        VectorsHttpRules.assertAll(http.get("rules"), http, core);
    }

    private static PublicKey publicKey(String name, JsonNode http, JsonNode core) {
        JsonNode k = http.get("keys").has(name) ? http.get("keys").get(name) : core.get("keys").get(name);
        return Crypto.decodePublicKey(Base64Url.decode(k.get("pub").asText()));
    }

    private static void assertResponse(JsonNode c, JsonNode http, JsonNode core) {
        String name = c.get("name").asText();
        JsonNode policy = core.get("policies").get(c.get("policy").asText());
        Map<String, PublicKey> ring = new LinkedHashMap<>();
        c.get("keyring").properties().forEach(e -> ring.put(e.getKey(), publicKey(e.getValue().asText(), http, core)));
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        long now = c.get("now").asLong();
        Verifier verifier = new Verifier(new VerifierConfig(Keyring.of(ring),
                Base64Url.decode(policy.get("root").asText()), policy.get("rootId").asText(),
                c.get("policyNotAfter").asLong(), origins, c.get("sess").asText(),
                new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong()));
        List<Stamp> sent = new ArrayList<>();
        c.get("sent").forEach(s -> sent.add(stamp(s)));
        MerkleProof proof = MerkleProof.parse(Vectors.text(policy.get("proofs").get(c.get("proofRoute").asText())));
        JsonNode header = c.get("responseHeader");
        HttpWire.ResponseCheck check = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            check = HttpWire.verifyResponse(verifier, sent, proof, header.isNull() ? null : header.asText(),
                    c.get("status").asInt(), HexFormat.of().parseHex(c.get("body").asText()), c.get("caller").asText());
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
