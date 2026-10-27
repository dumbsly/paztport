// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SessionsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeyPair clientPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair serverPolicy = Crypto.generateEd25519KeyPair();
    private final String clientKey = key(clientPolicy);
    private final String serverKey = key(serverPolicy);
    private final Map<String, String> clientRing = Map.of("session", "client-service-key");
    private final SignedRoot clientRoot = SignedRoot.sign(Crypto.sha256("c".getBytes()), "v1", clientPolicy.getPrivate());
    private final SignedRoot serverRoot = SignedRoot.sign(Crypto.sha256("s".getBytes()), "v1", serverPolicy.getPrivate());

    private static String key(KeyPair pair) {
        return Base64Url.encode(Crypto.encodePublicKey(pair.getPublic()));
    }

    private SessionRequest request(SignedRoot root) {
        return new SessionRequest(root, clientKey, clientRing,
                KeyringFile.sign(clientRing, clientKey, clientPolicy.getPrivate()).sig(), Sessions.newNonce());
    }

    private SessionReply reply(SessionRequest req, SignedRoot root, String status) {
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                root == null ? null : root.sig(), req.nonce(), nonce, req.clientPolicyKey(), req.clientKeyring());
        return Sessions.signReply(new SessionReply(root, serverKey, Map.of("pay", "server-key"), nonce, sess, status,
                status.equals("attested") ? List.of() : List.of("send"), null), serverPolicy.getPrivate());
    }

    private JsonNode wire(SessionReply r) {
        return JSON.valueToTree(r.toJson());
    }

    @Test
    void attestedRoundTrip() {
        SessionRequest req = request(clientRoot);
        assertEquals("attested", Sessions.status(req, serverRoot, serverPolicy.getPublic(), Set.of(clientKey)));
        assertTrue(Sessions.opensSession(req));

        SessionReply reply = reply(req, serverRoot, "attested");
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(wire(reply), req, serverKey));
        assertEquals(Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), reply.nonce(), clientKey,
                clientRing), reply.sess());
        // the request survives its own wire form
        assertEquals(req, Sessions.parseRequest(req.toJson()));
    }

    @Test
    void unsafeWhen() {
        Set<String> pinned = Set.of(clientKey);
        PublicKey own = serverPolicy.getPublic();
        assertEquals("unsafe", Sessions.status(request(null), serverRoot, own, pinned), "null client root");
        assertEquals("unsafe", Sessions.status(request(clientRoot), serverRoot, own, Set.of(key(serverPolicy))), "unpinned");
        assertEquals("unsafe", Sessions.status(request(clientRoot), serverRoot, own, Set.of()), "empty pins");
        SessionRequest good = request(clientRoot);
        SessionRequest wrongSig = new SessionRequest(clientRoot, clientKey, clientRing,
                Base64Url.encode(new byte[64]), good.nonce());
        assertEquals("unsafe", Sessions.status(wrongSig, serverRoot, own, pinned), "wrong keyring sig");
        SessionRequest legacy = new SessionRequest(clientRoot, clientKey, clientRing, null, good.nonce());
        assertTrue(legacy.legacy());
        assertEquals("unsafe", Sessions.status(legacy, serverRoot, own, pinned), "legacy");
        assertEquals("unsafe", Sessions.status(good, null, own, pinned), "no server root");
        assertEquals("attested", Sessions.status(good, serverRoot, own, pinned));
    }

    @Test
    void checkReplyOutcomes() {
        SessionRequest req = request(clientRoot);
        SessionReply attested = reply(req, serverRoot, "attested");

        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(JSON.valueToTree("nope"), req, serverKey));
        ObjectNode noStatus = (ObjectNode) wire(attested);
        noStatus.remove("status");
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(noStatus, req, serverKey));
        assertEquals(ReplyCheck.PIN_MISMATCH, Sessions.checkReply(wire(attested), req, key(clientPolicy)));

        ObjectNode altered = (ObjectNode) wire(attested);
        altered.put("nonce", Sessions.newNonce());
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(altered, req, serverKey));

        SessionReply nullRoot = reply(req, null, "attested");
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(wire(nullRoot), req, serverKey));

        SessionReply unsafe = reply(req, serverRoot, "unsafe");
        assertEquals(ReplyCheck.UNSAFE, Sessions.checkReply(wire(unsafe), req, serverKey));
        assertNotNull(unsafe.sig());
    }

    @Test
    void parseRequestRejects() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Sessions.parseRequest(JSON.readTree("[]")));
        ObjectNode ok = request(clientRoot).toJson();
        for (String[] bad : new String[][] {{"clientRoot", "5"}, {"clientKeyring", "{\"a\":1}"}, {"nonce", "7"}}) {
            ObjectNode o = ok.deepCopy();
            o.set(bad[0], JSON.readTree(bad[1]));
            assertThrows(IllegalArgumentException.class, () -> Sessions.parseRequest(o), bad[0]);
        }
        ObjectNode odd = ok.deepCopy();
        odd.put("clientKeyringSig", 5);
        assertEquals("", Sessions.parseRequest(odd).clientKeyringSig());
        odd.remove("clientKeyringSig");
        assertTrue(Sessions.parseRequest(odd).legacy());
    }

    @Test
    void opensSessionFalse() {
        SessionRequest ok = request(clientRoot);
        assertTrue(Sessions.opensSession(ok));
        SessionRequest shortNonce = new SessionRequest(clientRoot, clientKey, clientRing, ok.clientKeyringSig(),
                Base64Url.encode(new byte[15]));
        assertFalse(Sessions.opensSession(shortNonce));
        SessionRequest shortSig = new SessionRequest(new SignedRoot("v1", clientRoot.root(), Base64Url.encode(new byte[63])),
                clientKey, clientRing, ok.clientKeyringSig(), ok.nonce());
        assertFalse(Sessions.opensSession(shortSig));
    }
}
