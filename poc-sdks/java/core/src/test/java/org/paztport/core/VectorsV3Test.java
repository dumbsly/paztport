// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays the committed v3 vectors in {@code spec/vectors/v3.json}, the file the TypeScript SDK also reads. One
 * test method per section, so a failure names the section.
 */
class VectorsV3Test {

    static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v3.json");
    }

    @Test
    void influence() {
        for (JsonNode c : vectors.get("influence")) {
            String name = c.get("name").asText();
            List<InfluenceEntry> normalised = Influence.normalise(Influence.parse(c.get("entries")));
            assertEquals(c.get("normalized"), Influence.toJson(normalised), name);
            assertEquals(c.get("commitment").asText(), Influence.commit(Influence.parse(c.get("entries"))), name);
        }
    }

    @Test
    void rule() {
        for (JsonNode c : vectors.get("rule")) {
            List<InfluenceFact> facts = new ArrayList<>();
            for (JsonNode f : c.get("influence")) {
                facts.add(new InfluenceFact(
                        InfluenceClass.fromWire(f.get("cls").asText()),
                        f.has("owner") ? f.get("owner").asText() : null));
            }
            JsonNode dest = c.get("destinationOwner");
            String owner = dest == null || dest.isNull() ? null : dest.asText();
            assertEquals(c.get("refused").asBoolean(), InfluenceRule.publicWriteRefused(facts, owner),
                    c.get("name").asText());
        }
    }

    private static StampV3 stamp(JsonNode s) {
        return new StampV3(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
                s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), "");
    }

    private static PrivateKey priv(String name) {
        return Crypto.decodePrivateKey(Base64Url.decode(vectors.get("keys").get(name).get("priv").asText()));
    }

    private static Map<String, String> services(JsonNode node) {
        Map<String, String> m = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> m.put(e.getKey(), e.getValue().asText()));
        return m;
    }

    @Test
    void signingBytesV3() {
        for (JsonNode c : vectors.get("signingBytesV3")) {
            assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp(c.get("stamp")).signingBytes()));
        }
    }

    @Test
    void signatures() {
        for (JsonNode c : vectors.get("signatures")) {
            JsonNode f = c.get("fields");
            StampV3 s = StampV3.sign(f.get("svc").asText(), f.get("inst").asText(), f.get("rid").asText(),
                    f.get("ts").asLong(), f.get("sess").asText(), f.get("rcv").asText(), f.get("bind").asText(),
                    f.get("infl").asText(), f.get("prev").asText(), priv(c.get("key").asText()));
            assertEquals(c.get("sig").asText(), s.sig());
        }
    }

    @Test
    void keyring() {
        for (JsonNode c : vectors.get("keyring")) {
            String name = c.get("name").asText();
            JsonNode signed = c.get("signed");
            String policy = signed.get("policy").asText();
            Map<String, String> svcs = services(signed.get("services"));
            assertEquals(c.get("signingBytes").asText(),
                    Base64Url.encode(KeyringFile.signingBytes(policy, svcs)), name);
            if (c.get("name").asText().equals("signed")) {
                assertEquals(c.get("sig").asText(),
                        KeyringFile.sign(svcs, policy, priv(c.get("policyKey").asText())).sig(), name);
            }
            KeyringFile file = new KeyringFile(svcs, policy, signed.get("sig").asText());
            String pin = vectors.get("keys").get(c.get("policyKey").asText()).get("pub").asText();
            assertEquals(c.get("verifies").asBoolean(), file.verifies(pin), name);
        }
    }

    @Test
    void replyCert() {
        JsonNode cases = vectors.get("replyCert");
        assertTrue(cases != null && cases.size() > 0, "replyCert section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            ReplyCert cert = ReplyCert.parse(c.get("cert"));
            assertEquals(c.get("signingBytes").asText(), Base64Url.encode(
                    ReplyCert.signingBytes(cert.policy(), cert.svc(), cert.key(), cert.notAfter())), name);
            String pin = vectors.get("keys").get(c.get("pin").asText()).get("pub").asText();
            assertEquals(c.get("verifies").asBoolean(), cert.verifies(pin), name);
            // Every certificate that verifies is reproduced byte for byte by issuing it.
            if (c.get("verifies").asBoolean()) {
                assertEquals(cert.sig(), ReplyCert.issue(cert.policy(), cert.svc(), cert.key(), cert.notAfter(),
                        priv(c.get("signer").asText())).sig(), name);
            }
        }
    }

    static Keyring keyring(JsonNode names) {
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        names.fields().forEachRemaining(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(vectors.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        return Keyring.of(keys);
    }

    @Test
    void verify() {
        for (JsonNode c : vectors.get("verify")) {
            String name = c.get("name").asText();
            JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
            Set<String> origins = new LinkedHashSet<>();
            c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
            long now = c.get("now").asLong();
            VerifierConfigV3 cfg = new VerifierConfigV3(keyring(c.get("keyring")),
                    Base64Url.decode(policy.get("root").asText()), policy.get("rootId").asText(), origins,
                    c.get("sess").asText(), new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                    c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong());
            JsonNode route = c.get("proofRoute");
            JsonNode peer = c.get("peer");
            VerifyInputV3 in = new VerifyInputV3(c.get("chain"), c.get("expectedBind").asText(), c.get("influence"),
                    route.isNull() ? null : policy.get("proofs").get(route.asText()), c.get("receiver").asText(),
                    c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                    peer.isNull() ? null : new Peer(peer.get("svc").asText(), peer.get("inst").asText()));
            VerifierV3 verifier = new VerifierV3(cfg);
            VerifyResult result = null;
            for (int i = 0; i < c.get("uses").asInt(); i++) {
                result = verifier.verify(in);
            }
            JsonNode want = c.get("expected");
            assertEquals(new VerifyResult(ReasonCode.valueOf(want.get("reason").asText()),
                    want.get("suspectSvc").asText(), want.get("suspectInst").asText()), result, name);
        }
    }

    /** The offline inputs a case gives; {@code run} absent means the run's recorded times are not compared. */
    static OfflineInput offlineInput(JsonNode c, JsonNode policy) {
        JsonNode t = c.get("recordedTs");
        Set<Long> run = null;
        if (t.has("run")) {
            run = new LinkedHashSet<>();
            for (JsonNode r : t.get("run")) {
                run.add(r.asLong());
            }
        }
        JsonNode route = c.get("proofRoute");
        return new OfflineInput(c.get("chain"), c.get("expectedBind").asText(), c.get("influence"),
                route.isNull() ? null : policy.get("proofs").get(route.asText()), c.get("receiver").asText(),
                c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(), c.get("rid").asText(),
                new RecordedTimes(t.get("last").asLong(), run), c.get("prompt").asText());
    }

    static OfflineConfig offlineConfig(JsonNode c, JsonNode policy) {
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        Set<String> seen = new LinkedHashSet<>();
        c.get("seen").forEach(k -> seen.add(k.asText()));
        return new OfflineConfig(keyring(c.get("keyring")), Base64Url.decode(policy.get("root").asText()),
                policy.get("rootId").asText(), origins, c.get("sess").asText(), seen, null,
                c.get("runMaxAgeMs").asLong(), c.get("callMaxAgeMs").asLong());
    }

    @Test
    void offline() {
        for (JsonNode c : vectors.get("offline")) {
            JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
            OfflineResult result = OfflineVerifier.verify(offlineInput(c, policy), offlineConfig(c, policy));
            JsonNode want = c.get("expected");
            assertEquals(new OfflineResult(ReasonCode.valueOf(want.get("reason").asText()),
                    want.get("suspectSvc").asText(), want.get("suspectInst").asText(),
                    want.get("legacy").asBoolean()), result, c.get("name").asText());
        }
    }

    static JsonNode offlineCase(String name) {
        for (JsonNode c : vectors.get("offline")) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException(name);
    }

    static JsonNode policy(JsonNode c) {
        return vectors.get("policies").get(c.get("policy").asText());
    }
}
