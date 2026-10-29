// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleHash;
import org.paztport.core.policy.MerkleLeaf;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.stamp.PathChainV1;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.StampV1;
import org.paztport.core.stamp.StampSignerV1;
import org.paztport.core.verify.VerifierV1;
import org.paztport.core.verify.VerifierConfigV1;
import org.paztport.core.verify.VerifyResult;

/**
 * Made the committed v1 file, {@code spec/vectors/v1.json}, and is kept only as the record of how. It is opt-in
 * ({@code -Dpaztport.exportVectors=true}) and writes to {@code -Dvectors.out=<file>}, or to
 * {@code target/v1-vectors.json} without it. It cannot reproduce the committed bytes: every run generates fresh
 * keys and salts, so a new export is a different file, and replacing the committed one would change every
 * recorded answer. Every verify case is first checked against the Java VerifierV1, so an export can never record
 * a wrong answer.
 */
class VectorExportTest {

    private static final long NOW = 1_000_000L;
    private static final long MAX_AGE = 5000;
    private static final int DEPTH = 8;

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair search = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final Map<String, KeyPair> keys = new LinkedHashMap<>();

    private static final String PAY = "gateway/orders/payment";
    private static final String ORD = "gateway/orders";
    private static final String SRCH = "gateway/search";

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String b64(byte[] b) {
        return Base64Url.encode(b);
    }

    private Map<String, Object> stampFields(StampV1 s, String keyName) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("svc", s.svc());
        fields.put("inst", s.inst());
        fields.put("rid", s.rid());
        fields.put("ts", s.ts());
        fields.put("bind", s.bind());
        fields.put("prev", s.prev());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fields", fields);
        m.put("signingBytes", b64(s.signingBytes()));
        m.put("sig", s.sig());
        m.put("key", keyName);
        return m;
    }

    private static Map<String, Object> stampJson(StampV1 s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("svc", s.svc());
        m.put("inst", s.inst());
        m.put("rid", s.rid());
        m.put("ts", s.ts());
        m.put("bind", s.bind());
        m.put("prev", s.prev());
        m.put("sig", s.sig());
        return m;
    }

    private Map<String, Object> chainJson(PathChainV1 c, List<StampV1> stamps) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("header", c.encode());
        List<Object> list = new ArrayList<>();
        for (StampV1 s : stamps) {
            list.add(stampJson(s));
        }
        m.put("stamps", list);
        return m;
    }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> verifyCase(String name, String chain, String proof, String method, String path,
            byte[] body, long now, int uses, ReasonCode expected) {
        Map<String, String> ring = new LinkedHashMap<>();
        ring.put("gateway", "gateway");
        ring.put("orders", "orders");
        ring.put("search", "search");
        List<String> origins = List.of("gateway");

        // Self-assert against the Java VerifierV1 before recording.
        Map<String, PublicKey> pubs = new LinkedHashMap<>();
        ring.forEach((svc, key) -> pubs.put(svc, keys.get(key).getPublic()));
        SignedRoot sr = SignedRoot.signOldForm(tree.root(), "v1", policy.getPrivate());
        VerifierConfigV1 cfg = VerifierConfigV1.pinned(Keyring.of(pubs), sr, policy.getPublic(), Set.copyOf(origins),
                MAX_AGE, new InMemoryNonceCache(), () -> now);
        VerifierV1 verifier = new VerifierV1(cfg);
        VerifyResult last = null;
        for (int i = 0; i < uses; i++) {
            last = verifier.verify(HttpVerifyRequestsV1.of(chain, proof, method, path, body, "payment"));
        }
        assertEquals(expected, last.reason(), "case " + name);

        return mapOf("name", name, "chainHeader", chain, "proofHeader", proof, "method", method, "path", path,
                "body", b64(body), "now", now, "maxAgeMs", MAX_AGE, "receivingService", "payment",
                "allowedOrigins", origins, "keyring", ring, "uses", uses, "expected", expected.name());
    }

    private MerkleTree tree;

    @Test
    @EnabledIfSystemProperty(named = "paztport.exportVectors", matches = "true")
    void export() throws IOException {
        keys.put("gateway", gateway);
        keys.put("orders", orders);
        keys.put("search", search);
        keys.put("policy", policy);

        Map<String, byte[]> salts = new LinkedHashMap<>();
        salts.put(PAY, Crypto.randomBytes(16));
        salts.put(ORD, Crypto.randomBytes(16));
        salts.put(SRCH, Crypto.randomBytes(16));
        tree = MerkleTree.build(
                List.of(new MerkleLeaf(salts.get(PAY), PAY), new MerkleLeaf(salts.get(ORD), ORD),
                        new MerkleLeaf(salts.get(SRCH), SRCH)),
                DEPTH, "v1");
        SignedRoot signedRoot = SignedRoot.signOldForm(tree.root(), "v1", policy.getPrivate());

        byte[] body = utf8("{\"amount\":100}");
        String bindPay = RequestBinding.compute("POST", "/pay", body);

        StampV1 s0 = StampSignerV1.sign("gateway", "gw-1", "rid-1", NOW, "bindGatewayToOrders", "", gateway.getPrivate());
        StampV1 s1 = StampSignerV1.sign("orders", "ord-1", "rid-1", NOW, bindPay, s0.sig(), orders.getPrivate());
        StampV1 s1s = StampSignerV1.sign("search", "s-1", "rid-1", NOW, bindPay, s0.sig(), search.getPrivate());
        PathChainV1 valid = new PathChainV1(List.of(s0, s1));
        PathChainV1 viaSearch = new PathChainV1(List.of(s0, s1s));

        Map<String, Object> out = new LinkedHashMap<>();

        Map<String, Object> keyJson = new LinkedHashMap<>();
        keys.forEach((n, kp) -> keyJson.put(n, mapOf(
                "pub", b64(Crypto.encodePublicKey(kp.getPublic())),
                "priv", b64(Crypto.encodePrivateKey(kp.getPrivate())))));
        out.put("keys", keyJson);

        out.put("stamps", List.of(stampFields(s0, "gateway"), stampFields(s1, "orders"), stampFields(s1s, "search")));
        out.put("chains", List.of(chainJson(valid, List.of(s0, s1)), chainJson(viaSearch, List.of(s0, s1s))));

        byte[] uniBody = utf8("{\"name\":\"Zoë 😀\"}");
        List<Object> bindings = new ArrayList<>();
        bindings.add(mapOf("method", "POST", "path", "/pay", "body", b64(body), "bind", bindPay));
        bindings.add(mapOf("method", "GET", "path", "/items", "body", b64(new byte[0]),
                "bind", RequestBinding.compute("GET", "/items", new byte[0])));
        bindings.add(mapOf("method", "PUT", "path", "/pé/😀", "body", b64(uniBody),
                "bind", RequestBinding.compute("PUT", "/pé/😀", uniBody)));
        out.put("bindings", bindings);

        // Merkle
        List<Object> leaves = new ArrayList<>();
        List<byte[]> leafHashes = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : salts.entrySet()) {
            byte[] h = MerkleHash.leaf(e.getValue(), e.getKey());
            leafHashes.add(h);
            leaves.add(mapOf("salt", b64(e.getValue()), "path", e.getKey(), "hash", b64(h)));
        }
        List<Object> nodes = List.of(mapOf("left", b64(leafHashes.get(0)), "right", b64(leafHashes.get(1)),
                "hash", b64(MerkleHash.node(leafHashes.get(0), leafHashes.get(1)))));
        Map<String, Object> proofs = new LinkedHashMap<>();
        Map<String, Object> proofHeaders = new LinkedHashMap<>();
        for (String p : salts.keySet()) {
            MerkleProof proof = tree.proofFor(p);
            assertEquals(true, proof.verify(p, tree.root()));
            proofs.put(p, mapOf("leafSalt", proof.leafSalt(), "siblings", proof.siblings(), "dirs", proof.dirs(),
                    "rootId", proof.rootId()));
            proofHeaders.put(p, proof.encode());
        }
        out.put("merkle", mapOf(
                "leaves", leaves, "nodes", nodes, "rootId", "v1", "root", b64(tree.root()),
                "signedRoot", mapOf("rootId", signedRoot.rootId(), "root", signedRoot.root(), "sig", signedRoot.sig()),
                "policyKey", "policy", "proofs", proofs, "proofHeaders", proofHeaders));

        // Verify cases, one per reason code plus OK.
        String payProof = tree.proofFor(PAY).encode();
        List<Object> cases = new ArrayList<>();
        cases.add(verifyCase("ok", valid.encode(), payProof, "POST", "/pay", body, NOW, 1, ReasonCode.OK));
        cases.add(verifyCase("chain-missing", null, payProof, "POST", "/pay", body, NOW, 1, ReasonCode.CHAIN_MISSING));
        StampV1 notOrigin = StampSignerV1.sign("search", "s-1", "rid-1", NOW, "b", "", search.getPrivate());
        cases.add(verifyCase("bad-origin", new PathChainV1(List.of(notOrigin)).encode(), payProof, "POST", "/pay", body,
                NOW, 1, ReasonCode.BAD_ORIGIN));
        StampV1 forged = StampSignerV1.sign("gateway", "evil", "rid-1", NOW, bindPay, "", search.getPrivate());
        cases.add(verifyCase("bad-signature", new PathChainV1(List.of(forged)).encode(), payProof, "POST", "/pay", body,
                NOW, 1, ReasonCode.BAD_SIGNATURE));
        StampV1 broken = StampSignerV1.sign("orders", "ord-1", "rid-1", NOW, bindPay, b64(utf8("not-s0-sig")),
                orders.getPrivate());
        cases.add(verifyCase("broken-link", new PathChainV1(List.of(s0, broken)).encode(), payProof, "POST", "/pay",
                body, NOW, 1, ReasonCode.BROKEN_LINK));
        StampV1 old0 = StampSignerV1.sign("gateway", "gw-1", "rid-1", NOW - 6000, "bGW", "", gateway.getPrivate());
        StampV1 old1 = StampSignerV1.sign("orders", "ord-1", "rid-1", NOW - 6000, bindPay, old0.sig(),
                orders.getPrivate());
        cases.add(verifyCase("expired", new PathChainV1(List.of(old0, old1)).encode(), payProof, "POST", "/pay", body,
                NOW, 1, ReasonCode.EXPIRED));
        StampV1 otherRid = StampSignerV1.sign("orders", "ord-1", "rid-DIFFERENT", NOW, bindPay, s0.sig(),
                orders.getPrivate());
        cases.add(verifyCase("rid-mismatch", new PathChainV1(List.of(s0, otherRid)).encode(), payProof, "POST", "/pay",
                body, NOW, 1, ReasonCode.RID_MISMATCH));
        cases.add(verifyCase("binding-mismatch", valid.encode(), payProof, "POST", "/pay", utf8("{\"amount\":999}"),
                NOW, 1, ReasonCode.BINDING_MISMATCH));
        cases.add(verifyCase("replay", valid.encode(), payProof, "POST", "/pay", body, NOW, 2, ReasonCode.REPLAY));
        cases.add(verifyCase("path-not-allowed", viaSearch.encode(), tree.proofFor(SRCH).encode(), "POST", "/pay",
                body, NOW, 1, ReasonCode.PATH_NOT_ALLOWED));
        out.put("verify", cases);

        Path file = Path.of(System.getProperty("vectors.out", "target/v1-vectors.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        Files.write(file, mapper.writeValueAsBytes(out));
    }
}
