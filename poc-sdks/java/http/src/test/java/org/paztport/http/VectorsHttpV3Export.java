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
import org.paztport.core.Base64Url;
import org.paztport.core.ContentLabel;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.InfluenceClass;
import org.paztport.core.Keyring;
import org.paztport.core.MerkleProof;
import org.paztport.core.ReasonCode;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;

/**
 * Builds {@code spec/vectors/http-v3.json} and replays it. Unlike the v1 exporter this is deterministic: the
 * clock, rid and timestamps are fixed, the one new key is derived by {@code v3.json}'s rule, and Ed25519 signs
 * deterministically, so {@link #build} reproduces the committed bytes and {@code VectorsHttpV3Test} pins them.
 * The writer is opt-in so it never runs alongside the v1 exporter. This class is not matched by Surefire's default
 * includes, so name it: {@code (cd poc-sdks/java && mvn -q -pl http -am test -Dtest=VectorsHttpV3Export
 * -Dpaztport.exportHttpV3Vectors=true -Dvectors.out=<repo>/poc-sdks/spec/vectors/http-v3.json
 * -Dsurefire.failIfNoSpecifiedTests=false)}. {@link #build} replays every case it records, so an export can never record a
 * wrong answer.
 */
class VectorsHttpV3Export {

    private static final String ABOUT = "Paztport v3-over-HTTP conformance vectors. The keys, the `mesh` policy and"
            + " its proofs are the ones in v3.json, by name; only the `payment` key is new, derived by v3.json's rule"
            + " (seed = SHA-256(utf8(\"paztport-v3-vector-key:payment\")), the same PKCS#8 and SPKI encodings, both"
            + " base64url). resultHash maps a status and body (hex) to the result hash. requestBinding maps a method,"
            + " a target (the raw path plus `?` and the raw query when there is one) and a body (hex) to the request"
            + " binding. A responses case is a request chain `sent` from gateway to orders to payment and the"
            + " `responseHeader` payment returned; the caller `orders` checks it against `status` and `body` (hex)"
            + " with the proof the mesh policy holds for `proofRoute`, running the check `uses` times against one"
            + " nonce cache of nonceTtlMs, and expects the last result, with `labels` empty unless the reason is OK."
            + " Ed25519 is deterministic, so the file is reproduced byte for byte. Only the Java SDK speaks v3 over"
            + " HTTP, so the TypeScript SDK does not replay this file.";

    private static final long GATEWAY_TS = 1_767_225_598_500L;
    private static final long ORDERS_TS = 1_767_225_599_500L;
    private static final long RESPONSE_TS = 1_767_225_599_800L;
    private static final long NOW = 1_767_225_600_000L;
    private static final String RID = "rid-http-1";
    private static final String ROUTE = "gateway/orders/payment";
    private static final byte[] REQUEST_BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_BODY = "{\"paid\":true}".getBytes(StandardCharsets.UTF_8);
    private static final String KEY_PREFIX = "302e020100300506032b657004220420";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Finds a committed vector file by walking up from the working directory, from any module. */
    static JsonNode load(String name) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return MAPPER.readTree(Files.readAllBytes(candidate));
            }
        }
        throw new IllegalStateException("spec/vectors/" + name + " not found above " + dir);
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

    private static ArrayNode stampsJson(List<StampV3> stamps) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        stamps.forEach(s -> a.add(s.toJson()));
        return a;
    }

    private static ArrayNode labelsJson(List<ContentLabel> labels) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        labels.forEach(l -> a.add(l.toJson()));
        return a;
    }

    static ObjectNode build() throws IOException {
        JsonNode v3 = load("v3.json");
        KeyPair payment = derive("payment");
        PrivateKey gatewayKey = Crypto.decodePrivateKey(Base64Url.decode(v3.get("keys").get("gateway").get("priv").asText()));
        PrivateKey ordersKey = Crypto.decodePrivateKey(Base64Url.decode(v3.get("keys").get("orders").get("priv").asText()));
        JsonNode proof = v3.get("policies").get("mesh").get("proofs").get(ROUTE);
        MerkleProof sentProof = MerkleProof.fromJson(proof);

        // The request chain gateway -> orders -> payment, exactly as StamperV3 builds it in a mesh.
        StamperV3.Stamped toOrders = new StamperV3("gateway", "gw-1", gatewayKey, true, () -> RID, () -> GATEWAY_TS)
                .next(List.of(), "orders", "bind-gateway-to-orders", List.of(), null);
        StamperV3.Stamped toPayment = new StamperV3("orders", "ord-1", ordersKey, false, () -> RID, () -> ORDERS_TS)
                .next(toOrders.chain(), "payment", RequestBinding.compute("POST", "/pay", REQUEST_BODY), List.of(), null);
        List<StampV3> sent = toPayment.chain();
        StamperV3 responder = new StamperV3("payment", "pay-1", payment.getPrivate(), false, () -> RID, () -> RESPONSE_TS);

        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-receipt-1", "alice"));
        String okHash = HttpV3.resultHash(200, RESPONSE_BODY);
        StampV3 okStamp = responder.respond(sent, okHash, RID, labels);
        String okHeader = HttpV3.encodeResponse(okStamp, labels);
        // A properly signed response, but to the gateway rather than to the caller that sent the request.
        StampV3 toGateway = StampV3.sign("payment", "pay-1", RID, RESPONSE_TS, "", "gateway",
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
            o.put("hash", HttpV3.resultHash((int) c[0], body));
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

        ArrayNode responses = out.putArray("responses");
        responses.add(responseCase("response ok", sent, okHeader, 200, RESPONSE_BODY, 1,
                ReasonCode.OK, "payment", "pay-1", labels, okHash));
        responses.add(responseCase("response to wrong receiver", sent, HttpV3.encodeResponse(toGateway, labels), 200,
                RESPONSE_BODY, 1, ReasonCode.BINDING_MISMATCH, "", "", List.of(), okHash));
        responses.add(responseCase("labels altered", sent, HttpV3.encodeResponse(okStamp,
                List.of(new ContentLabel(InfluenceClass.PUBLIC, "cid-receipt-1", null))), 200, RESPONSE_BODY, 1,
                ReasonCode.BINDING_MISMATCH, "", "", List.of(), okHash));
        responses.add(responseCase("status altered", sent, okHeader, 500, RESPONSE_BODY, 1,
                ReasonCode.BINDING_MISMATCH, "", "", List.of(), HttpV3.resultHash(500, RESPONSE_BODY)));
        responses.add(responseCase("replayed response", sent, okHeader, 200, RESPONSE_BODY, 2,
                ReasonCode.REPLAY, "", "", List.of(), okHash));
        responses.forEach(c -> ((ObjectNode) c).put("proofRoute", ROUTE));

        // Replay what was just built, so an export can never record a wrong answer.
        assertAll(out, v3);
        return out;
    }

    private static String responseBinding(String resultHash, List<ContentLabel> labels) {
        return org.paztport.core.Bindings.response(resultHash, RID, labels);
    }

    private static ObjectNode responseCase(String name, List<StampV3> sent, String header, int status, byte[] body,
            int uses, ReasonCode reason, String suspectSvc, String suspectInst, List<ContentLabel> labels,
            String resultHash) {
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
        c.put("callMaxAgeMs", VerifierConfigV3.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfigV3.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfigV3.NONCE_TTL_MS);
        c.put("uses", uses);
        ObjectNode e = c.putObject("expected");
        e.put("reason", reason.name());
        e.put("suspectSvc", suspectSvc);
        e.put("suspectInst", suspectInst);
        e.set("labels", labelsJson(labels));
        e.put("resultHash", resultHash);
        return c;
    }

    private static StampV3 stamp(JsonNode s) {
        return new StampV3(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
                s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), s.get("sig").asText());
    }

    /** Replays every section of {@code http} through {@link HttpV3}; {@code v3} supplies the shared keys and policy. */
    static void assertAll(JsonNode http, JsonNode v3) {
        for (JsonNode c : http.get("resultHash")) {
            assertEquals(c.get("hash").asText(),
                    HttpV3.resultHash(c.get("status").asInt(), HexFormat.of().parseHex(c.get("body").asText())));
        }
        for (JsonNode c : http.get("requestBinding")) {
            assertEquals(c.get("bind").asText(), RequestBinding.compute(c.get("method").asText(),
                    c.get("target").asText(), HexFormat.of().parseHex(c.get("body").asText())));
        }
        for (JsonNode c : http.get("responses")) {
            assertResponse(c, http, v3);
        }
    }

    private static PublicKey publicKey(String name, JsonNode http, JsonNode v3) {
        JsonNode k = http.get("keys").has(name) ? http.get("keys").get(name) : v3.get("keys").get(name);
        return Crypto.decodePublicKey(Base64Url.decode(k.get("pub").asText()));
    }

    private static void assertResponse(JsonNode c, JsonNode http, JsonNode v3) {
        String name = c.get("name").asText();
        JsonNode policy = v3.get("policies").get(c.get("policy").asText());
        Map<String, PublicKey> ring = new LinkedHashMap<>();
        c.get("keyring").fields().forEachRemaining(e -> ring.put(e.getKey(), publicKey(e.getValue().asText(), http, v3)));
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        long now = c.get("now").asLong();
        VerifierV3 verifier = new VerifierV3(new VerifierConfigV3(Keyring.of(ring),
                Base64Url.decode(policy.get("root").asText()), policy.get("rootId").asText(), origins,
                c.get("sess").asText(), new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong()));
        List<StampV3> sent = new ArrayList<>();
        c.get("sent").forEach(s -> sent.add(stamp(s)));
        MerkleProof proof = MerkleProof.fromJson(policy.get("proofs").get(c.get("proofRoute").asText()));
        JsonNode header = c.get("responseHeader");
        HttpV3.ResponseCheck check = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            check = HttpV3.verifyResponse(verifier, sent, proof, header.isNull() ? null : header.asText(),
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
    @EnabledIfSystemProperty(named = "paztport.exportHttpV3Vectors", matches = "true")
    void export() throws IOException {
        Path file = Path.of(System.getProperty("vectors.out", "target/http-v3.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, render(build()));
    }
}
