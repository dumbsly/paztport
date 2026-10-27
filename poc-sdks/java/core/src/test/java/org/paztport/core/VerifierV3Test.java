// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.TextNode;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The edges of the v3 live verifier that the shared vectors do not reach: hostile input, a null peer, the pin. */
class VerifierV3Test {

    private static JsonNode vectors;
    private static JsonNode peerOk;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v3.json");
        for (JsonNode c : vectors.get("verify")) {
            if (c.get("name").asText().equals("peer ok")) {
                peerOk = c;
            }
        }
    }

    private static VerifierV3 verifier() {
        JsonNode c = peerOk;
        JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        c.get("keyring").fields().forEachRemaining(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(vectors.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        long now = c.get("now").asLong();
        return new VerifierV3(new VerifierConfigV3(Keyring.of(keys), Base64Url.decode(policy.get("root").asText()),
                policy.get("rootId").asText(), Set.of("session"), c.get("sess").asText(),
                new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now, c.get("callMaxAgeMs").asLong(),
                c.get("runMaxAgeMs").asLong()));
    }

    private static VerifyInputV3 input(JsonNode stamps, String bind, JsonNode influence, JsonNode proof, Peer peer) {
        JsonNode policy = vectors.get("policies").get(peerOk.get("policy").asText());
        JsonNode good = policy.get("proofs").get(peerOk.get("proofRoute").asText());
        return new VerifyInputV3(stamps, bind, influence, proof == null ? good : proof, peerOk.get("receiver").asText(),
                peerOk.get("receiverInRoute").asBoolean(), peerOk.get("nonceKey").asText(), peer);
    }

    private static String bind() {
        return peerOk.get("expectedBind").asText();
    }

    @Test
    void neverThrows() {
        JsonNode chain = peerOk.get("chain");
        JsonNode infl = peerOk.get("influence");
        assertEquals(ReasonCode.CHAIN_MISSING,
                verifier().verify(input(new TextNode("x"), bind(), infl, null, null)).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(input(null, bind(), infl, null, null)).reason());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH,
                verifier().verify(input(chain, bind(), JsonNodeFactory.instance.objectNode(), null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED,
                verifier().verify(input(chain, bind(), infl, new TextNode("x"), null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(input(chain, null, infl, null, null)).reason());
    }

    @Test
    void nullPeerIsNoPeer() {
        VerifyResult r = verifier().verify(input(peerOk.get("chain"), bind(), peerOk.get("influence"), null, null));
        assertEquals(new VerifyResult(ReasonCode.OK, "pi", "pi-1"), r);
    }

    @Test
    void pinnedRefusesUnsignedKeyring() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        byte[] root = new byte[32];
        SignedRoot signed = SignedRoot.sign(root, "v1", policy.getPrivate());
        KeyringFile unsigned = new KeyringFile(Map.of(), pin, null);
        assertThrows(IllegalArgumentException.class, () -> VerifierConfigV3.pinned(unsigned, signed, pin,
                Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
        KeyringFile good = KeyringFile.sign(Map.of(), pin, policy.getPrivate());
        VerifierConfigV3 cfg = VerifierConfigV3.pinned(good, signed, pin, Set.of("session"), "s",
                new InMemoryNonceCache(), () -> 0L, 5000, 5000);
        assertEquals("v1", cfg.rootId());
        KeyPair other = Crypto.generateEd25519KeyPair();
        SignedRoot forged = SignedRoot.sign(root, "v1", other.getPrivate());
        assertThrows(IllegalArgumentException.class, () -> VerifierConfigV3.pinned(good, forged, pin,
                Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
    }
}
