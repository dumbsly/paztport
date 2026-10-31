// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/** A session request read from the body it arrives in: strictly, in the encoding its bytes show. */
class SessionRequestTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    @Test
    void parsesRequestJson() throws Exception {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Map<String, String> ring = Map.of("payment", "payment-key");
        SessionRequest req = SessionRequest.of(
                SignedRoot.sign(Crypto.sha256("r".getBytes(StandardCharsets.UTF_8)), "v1",
                        NOT_AFTER, policy.getPrivate()),
                pin, KeyringFile.sign(ring, pin, NOT_AFTER, policy.getPrivate()), Sessions.newNonce());

        SessionRequest back = SessionRequest.parse(req.toJson().getBytes(StandardCharsets.UTF_8));

        assertEquals(req, back);
        // A body is read in the encoding its first bytes show, as it always has been: UTF-16, or UTF-8 behind a
        // byte order mark, reads as the same request.
        assertEquals(req, SessionRequest.parse(req.toJson().getBytes(StandardCharsets.UTF_16BE)));
        assertEquals(req, SessionRequest.parse(("\uFEFF" + req.toJson()).getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void refusesNonJsonAndTrailing() {
        for (String body : new String[] {"{", "{} {}", "[]"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> SessionRequest.parse(body.getBytes(StandardCharsets.UTF_8)), body);
        }
    }

    @Test
    void aMissingKeyringSignatureIsMalformed() throws Exception {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        ObjectNode wire = (ObjectNode) new ObjectMapper().readTree(SessionRequest.of(null, pin,
                KeyringFile.sign(Map.of("payment", "payment-key"), pin, NOT_AFTER, policy.getPrivate()),
                Sessions.newNonce()).toJson());

        wire.remove("clientKeyringSig");
        assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse(wire.toString()), "missing");
        for (JsonNode bad : new JsonNode[] {NullNode.instance, TextNode.valueOf(""), IntNode.valueOf(7)}) {
            ObjectNode o = wire.deepCopy();
            o.set("clientKeyringSig", bad);
            assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse(o.toString()), bad.toString());
        }
    }
}
