// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionReply;
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
    private final PartnerSessions sessions = partner(PartnerSessions.DEFAULT_MAX_SESSIONS_PER_PEER);
    private final PeerCert orders = new PeerCert(new Peer("orders", "10.0.0.8"), "CN=shop CA");

    private PartnerSessions partner(int maxSessionsPerPeer) {
        return PartnerSessions.builder()
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
            .maxSessionsPerPeer(maxSessionsPerPeer)
            .build();
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private byte[] request(String nonce) {
        return SessionRequest.of(null, pub(shopPolicy), shopKeyring, nonce).toJson().getBytes(StandardCharsets.UTF_8);
    }

    /** A request body's members, read as the partner reads it, for a test to alter. */
    private static Map<String, JsonValue> members(byte[] request) {
        return new LinkedHashMap<>(((JsonValue.Obj) JsonReader.wire(request)).members());
    }

    /** Members written back as an object's wire bytes. */
    private static byte[] wire(Map<String, JsonValue> members) {
        return JsonWriter.wire(new JsonValue.Obj(members));
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

        assertNotNull(sessions.find("CN=shop CA", "orders", sess(answer)), "kept for the peer that opened it");
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

    /**
     * A body is the request's canonical bytes, so a request file sent as saved, with a newline after it, is not a
     * readable request: it is refused as any other, with no stack trace and no 500, and opens nothing.
     */
    @Test
    void aBodyWithATrailingNewlineIsInvalidParams() throws IOException {
        // a peer holds one session, so a refused request that opened another would evict the first
        PartnerSessions one = partner(1);
        String kept = sess(HttpSessions.serve(body(request(Sessions.newNonce())), orders, one));
        byte[] request = request(Sessions.newNonce());
        byte[] saved = Arrays.copyOf(request, request.length + 1);
        saved[request.length] = '\n';

        HttpAnswer answer = HttpSessions.serve(body(saved), orders, one);

        assertEquals(400, answer.status());
        assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        assertNotNull(one.find("CN=shop CA", "orders", kept), "the refused request opened no session");
    }

    /** The same request in another member order is not its canonical bytes either. */
    @Test
    void aBodyInWireMemberOrderIsInvalidParams() throws IOException {
        PartnerSessions one = partner(1);
        String kept = sess(HttpSessions.serve(body(request(Sessions.newNonce())), orders, one));
        String request = new String(request(Sessions.newNonce()), StandardCharsets.UTF_8);
        int nonce = request.lastIndexOf(",\"nonce\":");
        String nonceFirst = "{" + request.substring(nonce + 1, request.length() - 1) + ","
                + request.substring(1, nonce) + "}";

        HttpAnswer answer = HttpSessions.serve(body(nonceFirst.getBytes(StandardCharsets.UTF_8)), orders, one);

        assertEquals(400, answer.status());
        assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        assertNotNull(one.find("CN=shop CA", "orders", kept), "the refused request opened no session");
    }

    /** The session id a 200 answer's reply names. */
    private static String sess(HttpAnswer answer) {
        assertEquals(200, answer.status());
        return SessionReply.parse(answer.json()).sess();
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
        // a peer holds one session, so a refused request that opened another would evict the first
        PartnerSessions one = partner(1);
        String kept = sess(HttpSessions.serve(body(request(Sessions.newNonce())), orders, one));
        Map<String, JsonValue> missing = members(request(Sessions.newNonce()));
        missing.remove("clientKeyringSig");

        HttpAnswer answer = HttpSessions.serve(body(wire(missing)), orders, one);

        assertEquals(400, answer.status());
        assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        assertNotNull(one.find("CN=shop CA", "orders", kept), "the refused request opened no session");
    }

    /** A request whose keyring or root has no {@code notAfter} is malformed, and opens no session. */
    @Test
    void clientMaterialWithoutNotAfterIsInvalidParams() throws IOException {
        PartnerSessions one = partner(1);
        String kept = sess(HttpSessions.serve(body(request(Sessions.newNonce())), orders, one));
        Map<String, JsonValue> noRingWindow = members(request(Sessions.newNonce()));
        noRingWindow.remove("clientKeyringNotAfter");
        Map<String, JsonValue> noRootWindow = members(SessionRequest.of(
                PolicyBuilder.build(List.of(List.of("orders", "psp")), 4, NOT_AFTER, shopPolicy.getPrivate())
                        .signedRoot(), pub(shopPolicy), shopKeyring, Sessions.newNonce()).toJson()
                .getBytes(StandardCharsets.UTF_8));
        Map<String, JsonValue> root = new LinkedHashMap<>(((JsonValue.Obj) noRootWindow.get("clientRoot")).members());
        root.remove("notAfter");
        noRootWindow.put("clientRoot", new JsonValue.Obj(root));

        for (Map<String, JsonValue> bad : List.of(noRingWindow, noRootWindow)) {
            HttpAnswer answer = HttpSessions.serve(body(wire(bad)), orders, one);

            assertEquals(400, answer.status());
            assertEquals("{\"error\":\"INVALID_PARAMS\"}", text(answer));
        }
        assertNotNull(one.find("CN=shop CA", "orders", kept), "the refused requests opened no session");
    }
}
