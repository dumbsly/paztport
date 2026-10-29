// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/** The handshake's HTTP body: strict parsing in, a fixed error shape out. */
class HttpSessionsTest {

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

        SessionRequest back = HttpSessions.parseRequest(new ObjectMapper().writeValueAsBytes(req.toJson()));

        assertEquals(req, back);
    }

    @Test
    void refusesNonJsonAndTrailing() {
        for (String body : new String[] {"{", "{} {}", "[]"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> HttpSessions.parseRequest(body.getBytes(StandardCharsets.UTF_8)), body);
        }
    }

    @Test
    void errorBody() {
        assertArrayEquals("{\"error\":\"NO_SESSION\"}".getBytes(StandardCharsets.UTF_8),
                HttpSessions.error(HttpSessions.NO_SESSION));
    }
}
