// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.StampV2;

/** Replays the committed v2 vectors in {@code spec/vectors/v2.json}, one test method per section. */
class VectorsV2Test {

    private static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v2.json");
    }

    @Test
    void commitInfluence() {
        JsonNode c = vectors.get("commitInfluence");
        assertEquals(c.get("expected").asText(), Influence.commit(Influence.parse(Vectors.json(c.get("entries")))));
    }

    @Test
    void signingBytesV2() {
        JsonNode c = vectors.get("signingBytesV2");
        JsonNode s = c.get("stamp");
        StampV2 stamp = new StampV2(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(),
                s.get("ts").asLong(), s.get("sess").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), "");
        assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp.signingBytes()));
    }

    @Test
    void bindPrompt() {
        JsonNode c = vectors.get("bindPrompt");
        assertEquals(c.get("expected").asText(), Bindings.prompt(c.get("prompt").asText()));
    }

    @Test
    void bindResponse() {
        JsonNode c = vectors.get("bindResponse");
        assertEquals(c.get("expected").asText(), Bindings.response(c.get("resultHash").asText(),
                c.get("callId").asText(), ContentLabel.parseAll(Vectors.json(c.get("labels")))));
    }

    @Test
    void deriveSessionId() {
        JsonNode d = vectors.get("deriveSessionId");
        JsonNode keys = d.get("keys");
        Map<String, String> keyring = new LinkedHashMap<>();
        keys.get("clientKeyring").properties().forEach(e -> keyring.put(e.getKey(), e.getValue().asText()));
        for (JsonNode c : d.get("cases")) {
            assertEquals(c.get("expected").asText(),
                    Sessions.deriveSessionId(fixed(c.get("clientRootSig")), fixed(c.get("serverRootSig")),
                            fixed("clientNonce"), fixed("serverNonce"), keys.get("clientPolicyKey").asText(), keyring),
                    c.get("name").asText());
        }
    }

    private static String fixed(JsonNode nameOrNull) {
        return nameOrNull.isNull() ? null : fixed(nameOrNull.asText());
    }

    /** The named fixed input: {@code length} consecutive bytes from {@code start}, base64url. */
    private static String fixed(String name) {
        JsonNode f = vectors.get("fixedInputs").get(name);
        byte[] bytes = new byte[f.get("length").asInt()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (f.get("start").asInt() + i);
        }
        String encoded = Base64Url.encode(bytes);
        assertEquals(f.get("encoded").asText(), encoded);
        return encoded;
    }
}
