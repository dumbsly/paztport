// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.security.PrivateKey;
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

    private static JsonNode vectors;

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
}
