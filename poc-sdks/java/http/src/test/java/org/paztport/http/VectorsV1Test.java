// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.Keyring;
import org.paztport.core.PathChainV1;
import org.paztport.core.ReasonCode;
import org.paztport.core.SignedRoot;
import org.paztport.core.StampV1;
import org.paztport.core.VerifierV1;
import org.paztport.core.VerifierConfigV1;
import org.paztport.core.VerifyResult;

/**
 * Replays the committed v1 vectors in {@code spec/vectors/v1.json}, the same file the TypeScript SDK reads, so
 * the two implementations are held to one set of recorded answers. The file is found by walking up from the
 * working directory, so the test does not depend on which module or directory Maven was started from.
 */
class VectorsV1Test {

    private static JsonNode vectors;
    private static final Map<String, PublicKey> PUBLIC_KEYS = new LinkedHashMap<>();

    @BeforeAll
    static void load() throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        Path file = null;
        for (Path d = dir; d != null && file == null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/v1.json");
            if (Files.isRegularFile(candidate)) {
                file = candidate;
            }
        }
        if (file == null) {
            throw new IllegalStateException("spec/vectors/v1.json not found above " + dir);
        }
        vectors = new ObjectMapper().readTree(Files.readAllBytes(file));
        vectors.get("keys").fields().forEachRemaining(e ->
                PUBLIC_KEYS.put(e.getKey(), Crypto.decodePublicKey(Base64Url.decode(e.getValue().get("pub").asText()))));
    }

    @Test
    void stampSigningBytesAndSignatures() {
        for (JsonNode s : vectors.get("stamps")) {
            JsonNode f = s.get("fields");
            StampV1 stamp = new StampV1(f.get("svc").asText(), f.get("inst").asText(), f.get("rid").asText(),
                    f.get("ts").asLong(), f.get("bind").asText(), f.get("prev").asText(), s.get("sig").asText());
            assertEquals(s.get("signingBytes").asText(), Base64Url.encode(stamp.signingBytes()));
            assertTrue(Crypto.verify(PUBLIC_KEYS.get(s.get("key").asText()), stamp.signingBytes(),
                    Base64Url.decode(stamp.sig())), "signature of " + stamp.svc());
        }
    }

    @Test
    void chainsRoundTrip() {
        for (JsonNode c : vectors.get("chains")) {
            String header = c.get("header").asText();
            List<StampV1> expected = new ArrayList<>();
            for (JsonNode s : c.get("stamps")) {
                expected.add(new StampV1(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(),
                        s.get("ts").asLong(), s.get("bind").asText(), s.get("prev").asText(), s.get("sig").asText()));
            }
            assertEquals(expected, PathChainV1.decode(header).stamps());
            assertEquals(header, new PathChainV1(expected).encode());
        }
    }

    @Test
    void requestBindings() {
        for (JsonNode b : vectors.get("bindings")) {
            assertEquals(b.get("bind").asText(), RequestBinding.compute(b.get("method").asText(),
                    b.get("path").asText(), Base64Url.decode(b.get("body").asText())));
        }
    }

    @Test
    void signedRootVerifies() {
        JsonNode m = vectors.get("merkle");
        JsonNode sr = m.get("signedRoot");
        assertEquals(m.get("root").asText(), sr.get("root").asText());
        assertTrue(new SignedRoot(sr.get("rootId").asText(), sr.get("root").asText(), sr.get("sig").asText())
                .verify(PUBLIC_KEYS.get(m.get("policyKey").asText())));
    }

    @Test
    void everyVerifyCaseGivesTheRecordedReason() {
        JsonNode m = vectors.get("merkle");
        JsonNode sr = m.get("signedRoot");
        SignedRoot signedRoot = new SignedRoot(sr.get("rootId").asText(), sr.get("root").asText(), sr.get("sig").asText());
        PublicKey policyKey = PUBLIC_KEYS.get(m.get("policyKey").asText());
        int cases = 0;
        for (JsonNode c : vectors.get("verify")) {
            Map<String, PublicKey> ring = new HashMap<>();
            c.get("keyring").fields().forEachRemaining(e -> ring.put(e.getKey(), PUBLIC_KEYS.get(e.getValue().asText())));
            Set<String> origins = new java.util.HashSet<>();
            c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
            long now = c.get("now").asLong();
            VerifierV1 verifier = new VerifierV1(VerifierConfigV1.pinned(Keyring.of(ring), signedRoot, policyKey, origins,
                    c.get("maxAgeMs").asLong(), new InMemoryNonceCache(), () -> now));
            String chain = c.get("chainHeader").isNull() ? null : c.get("chainHeader").asText();
            String proof = c.get("proofHeader").isNull() ? null : c.get("proofHeader").asText();
            byte[] body = Base64Url.decode(c.get("body").asText());
            VerifyResult last = null;
            for (int i = 0; i < c.get("uses").asInt(); i++) {
                last = verifier.verify(HttpVerifyRequestsV1.of(chain, proof, c.get("method").asText(),
                        c.get("path").asText(), body, c.get("receivingService").asText()));
            }
            assertEquals(ReasonCode.valueOf(c.get("expected").asText()), last.reason(), "case " + c.get("name").asText());
            cases++;
        }
        assertEquals(vectors.get("verify").size(), cases);
        assertArrayEquals(Base64Url.decode(m.get("root").asText()), Base64Url.decode(signedRoot.root()));
    }
}
