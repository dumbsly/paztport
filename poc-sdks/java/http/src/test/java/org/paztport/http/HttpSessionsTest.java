// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.verify.Peer;

/** The handshake's refusal body, and a partner's answer to one handshake, with no web framework. */
class HttpSessionsTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private final KeyPair shopPolicy = Crypto.generateEd25519KeyPair();
    private final KeyringFile shopKeyring = KeyringFile.sign(Map.of("orders",
            pub(Crypto.generateEd25519KeyPair())), pub(shopPolicy), NOT_AFTER, shopPolicy.getPrivate());
    private final KeyPair pspPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair pspKey = Crypto.generateEd25519KeyPair();
    private final PartnerSessions sessions = PartnerSessions.builder()
            .ownRoot(PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, NOT_AFTER, pspPolicy.getPrivate())
                    .signedRoot())
            .ownKeyring(KeyringFile.sign(Map.of("psp", pub(pspKey)), pub(pspPolicy), NOT_AFTER,
                    pspPolicy.getPrivate()))
            .ownPolicyKey(pub(pspPolicy))
            .ownService("psp")
            .ownServiceKey(pspKey.getPrivate())
            .ownReplyCert(ReplyCert.issue(pub(pspPolicy), "psp", pub(pspKey),
                    System.currentTimeMillis() + 7 * 86_400_000L, pspPolicy.getPrivate()))
            .pinnedClientKeys(Set.of(pub(shopPolicy)))
            .clientOrigins(Set.of("orders"))
            .callMaxAgeMs(5000)
            .build();
    private final PeerCert orders = new PeerCert(new Peer("orders", "10.0.0.8"), "CN=shop CA");

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private byte[] request(String nonce) {
        return SessionRequest.of(null, pub(shopPolicy), shopKeyring, nonce).toJson().getBytes(StandardCharsets.UTF_8);
    }

    private static InputStream body(byte[] bytes) {
        return new ByteArrayInputStream(bytes);
    }

    private static String text(HttpAnswer answer) {
        return new String(answer.json(), StandardCharsets.UTF_8);
    }

    @Test
    void errorBody() {
        assertArrayEquals("{\"error\":\"NO_SESSION\"}".getBytes(StandardCharsets.UTF_8),
                HttpSessions.error(HttpSessions.NO_SESSION));
    }

    @Test
    void aHandshakeIsAnsweredWithTheSignedReply() throws IOException {
        HttpAnswer answer = HttpSessions.serve(body(request(Sessions.newNonce())), orders, sessions);

        assertEquals(200, answer.status());
        String sess = new ObjectMapper().readTree(answer.json()).get("sess").asText();
        assertNotNull(sessions.find("CN=shop CA", "orders", sess), "kept for the peer that opened it");
    }

    // The peer comes from the certificate alone, so a request with none to give opens nothing and is not read.
    @Test
    void withoutAPeerNothingIsOpenedAndTheBodyIsNotRead() throws IOException {
        InputStream unread = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("read");
            }
        };
        for (PeerCert peer : new PeerCert[] {null, new PeerCert(new Peer("", "10.0.0.8"), "CN=shop CA"),
                new PeerCert(new Peer("orders", "10.0.0.8"), "")}) {
            HttpAnswer answer = HttpSessions.serve(unread, peer, sessions);

            assertEquals(400, answer.status());
            assertEquals("{\"error\":\"NO_SESSION\"}", text(answer));
        }
    }

    @Test
    void aBodyThatIsNotARequestIsInvalidParams() throws IOException {
        for (byte[] bad : List.of("{}".getBytes(StandardCharsets.UTF_8), "not json".getBytes(StandardCharsets.UTF_8),
                new byte[HttpSessions.MAX_BODY_BYTES + 1])) {
            HttpAnswer answer = HttpSessions.serve(body(bad), orders, sessions);

            assertEquals(400, answer.status());
            assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        }
    }

    @Test
    void aReadableRequestThatOpensNoSessionIsNoSession() throws IOException {
        String shortNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[15]);

        HttpAnswer answer = HttpSessions.serve(body(request(shortNonce)), orders, sessions);

        assertEquals(400, answer.status());
        assertEquals("{\"error\":\"NO_SESSION\"}", text(answer));
    }

    @Test
    void aRequestWithNoKeyringSignatureIsInvalidParams() throws IOException {
        ObjectNode missing = (ObjectNode) new ObjectMapper().readTree(request(Sessions.newNonce()));
        missing.remove("clientKeyringSig");

        HttpAnswer answer = HttpSessions.serve(body(missing.toString().getBytes(StandardCharsets.UTF_8)), orders,
                sessions);

        assertEquals(400, answer.status());
        assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        // nothing was opened: the answer names no session, and the signed request's own session id is not kept
        assertNull(new ObjectMapper().readTree(answer.json()).get("sess"));
        String signed = new ObjectMapper().readTree(HttpSessions.serve(body(request(Sessions.newNonce())), orders,
                sessions).json()).get("sess").asText();
        assertNotNull(sessions.find("CN=shop CA", "orders", signed), "a signed request opens one");
        assertNull(sessions.find("CN=shop CA", "orders", ""), "the refused one opened none");
    }
}