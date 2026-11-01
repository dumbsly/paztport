// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

class SessionsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long NOW = 1_767_225_600_000L;
    /** The roots' and keyrings' window, 2028-01-01: unlike any certificate's, so a test can rewrite one. */
    private static final long NOT_AFTER = 1_830_297_600_000L;
    private static final long MAX_SAFE = (1L << 53) - 1;

    private final KeyPair clientPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair serverPolicy = Crypto.generateEd25519KeyPair();
    private final String clientKey = key(clientPolicy);
    private final String serverKey = key(serverPolicy);
    private final Map<String, String> clientRing = Map.of("session", "client-service-key");
    private final SignedRoot clientRoot =
            SignedRoot.sign(Crypto.sha256("c".getBytes()), "v1", NOT_AFTER, clientPolicy.getPrivate());
    private final SignedRoot serverRoot =
            SignedRoot.sign(Crypto.sha256("s".getBytes()), "v1", NOT_AFTER, serverPolicy.getPrivate());
    private final KeyringFile clientKeyring = KeyringFile.sign(clientRing, clientKey,
            NOT_AFTER, clientPolicy.getPrivate());
    private final KeyringFile serverKeyring = KeyringFile.sign(Map.of("pay", "server-key"), serverKey,
            NOT_AFTER, serverPolicy.getPrivate());

    private static String key(KeyPair pair) {
        return Base64Url.encode(Crypto.encodePublicKey(pair.getPublic()));
    }

    private SessionRequest request(SignedRoot root) {
        return SessionRequest.of(root, clientKey, clientKeyring, Sessions.newNonce());
    }

    /** The server's status for {@code req} at {@code NOW}: its own root and keyring, the client's key pinned. */
    private String status(SessionRequest req) {
        return Sessions.status(req, serverRoot, serverKeyring, serverPolicy.getPublic(), Set.of(clientKey), NOW);
    }

    private SessionReply reply(SessionRequest req, SignedRoot root, String status) {
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                root == null ? null : root.sig(), req.nonce(), nonce, req.clientPolicyKey(), req.clientKeyring());
        // The policy-key form: no keyring signature or certificate, signed by the policy key.
        return Sessions.signReply(new SessionReply(root, serverKey, Map.of("pay", "server-key"), null, null, null,
                nonce, sess, status, status.equals("attested") ? List.of() : List.of("send"), null),
                serverPolicy.getPrivate());
    }

    private JsonNode wire(SessionReply r) {
        return tree(r.toJson());
    }

    private static ObjectNode tree(String json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The client's check of a reply held as a tree, so a test can alter it first. */
    private static ReplyCheck check(JsonNode reply, SessionRequest req, String pin, String entry, long now) {
        return Sessions.checkReply(reply.toString(), req, pin, entry, now);
    }

    private static SessionRequest parse(JsonNode request) {
        return SessionRequest.parse(request.toString());
    }

    @Test
    void attestedRoundTrip() {
        SessionRequest req = request(clientRoot);
        assertEquals("attested", status(req));
        assertTrue(Sessions.opensSession(req));

        SessionReply reply = reply(req, serverRoot, "attested");
        assertEquals(ReplyCheck.ATTESTED, check(wire(reply), req, serverKey, "pay", NOW));
        assertEquals(Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), reply.nonce(), clientKey,
                clientRing), reply.sess());
        // the request survives its own wire form
        assertEquals(req, SessionRequest.parse(req.toJson()));
    }

    @Test
    void unsafeWhen() {
        Set<String> pinned = Set.of(clientKey);
        PublicKey own = serverPolicy.getPublic();
        assertEquals("unsafe", status(request(null)), "null client root");
        assertEquals("unsafe", Sessions.status(request(clientRoot), serverRoot, serverKeyring, own,
                Set.of(key(serverPolicy)), NOW), "unpinned");
        assertEquals("unsafe", Sessions.status(request(clientRoot), serverRoot, serverKeyring, own, Set.of(), NOW),
                "empty pins");
        SessionRequest good = request(clientRoot);
        SessionRequest wrongSig = new SessionRequest(clientRoot, clientKey, clientRing,
                Base64Url.encode(new byte[64]), NOT_AFTER, good.nonce());
        assertEquals("unsafe", status(wrongSig), "wrong keyring sig");
        assertEquals("unsafe", Sessions.status(good, null, serverKeyring, own, pinned, NOW), "no server root");
        assertEquals("attested", status(good));
    }

    @Test
    void checkReplyOutcomes() {
        SessionRequest req = request(clientRoot);
        SessionReply attested = reply(req, serverRoot, "attested");

        assertEquals(ReplyCheck.MALFORMED_REPLY,
                check(JSON.valueToTree("nope"), req, serverKey, "pay", NOW));
        ObjectNode noStatus = (ObjectNode) wire(attested);
        noStatus.remove("status");
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(noStatus, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.PIN_MISMATCH, check(wire(attested), req, key(clientPolicy), "pay", NOW));

        ObjectNode altered = (ObjectNode) wire(attested);
        altered.put("nonce", Sessions.newNonce());
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(altered, req, serverKey, "pay", NOW));

        SessionReply nullRoot = reply(req, null, "attested");
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(wire(nullRoot), req, serverKey, "pay", NOW));

        SessionReply unsafe = reply(req, serverRoot, "unsafe");
        assertEquals(ReplyCheck.UNSAFE, check(wire(unsafe), req, serverKey, "pay", NOW));
        assertNotNull(unsafe.sig());
    }

    /**
     * The entry-key form: signed by the entry service's key, which the reply's signed keyring and certificate
     * vouch for. The forged cases: an expired certificate, an entry the client did not configure, the same reply
     * signed by the policy key (the form is decided by the fields, so the pin is never tried), and a certificate
     * the record drops (the policy-key form then needs the policy key, which did not sign it).
     */
    @Test
    void entryKeyForm() throws Exception {
        KeyPair entry = Crypto.generateEd25519KeyPair();
        Map<String, String> ring = Map.of("pay", key(entry), "ledger", "ledger-key");
        KeyringFile signedRing = KeyringFile.sign(ring, serverKey, NOT_AFTER, serverPolicy.getPrivate());
        ReplyCert cert = ReplyCert.issue(serverKey, "pay", key(entry), NOW + 1000, serverPolicy.getPrivate());
        SessionRequest req = request(clientRoot);
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), nonce, clientKey,
                clientRing);
        SessionReply unsigned = new SessionReply(serverRoot, serverKey, ring, signedRing.sig(), NOT_AFTER, cert, nonce,
                sess, "attested", List.of(), null);

        JsonNode byEntry = wire(Sessions.signReply(unsigned, entry.getPrivate()));
        assertEquals(JSON.readTree(cert.toJson()), byEntry.get("serverReplyCert"));
        assertEquals(ReplyCheck.ATTESTED, check(byEntry, req, serverKey, "pay", NOW + 1000));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "pay", NOW + 1001));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "ledger", NOW));

        JsonNode byPolicy = wire(Sessions.signReply(unsigned, serverPolicy.getPrivate()));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byPolicy, req, serverKey, "pay", NOW));

        ObjectNode noCert = (ObjectNode) byEntry.deepCopy();
        noCert.remove("serverReplyCert");
        noCert.remove("serverKeyringSig");
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(noCert, req, serverKey, "pay", NOW));
    }

    /**
     * A certificate's {@code notAfter} is judged by value, and the reply's signature covers the reply's parsed
     * value, so a reply whose certificate writes the same integer as {@code 1798761600000.0} or {@code 1.7987616e12}
     * gets the verdict the plain digits get, as it does in TypeScript. A fraction is no integer by value and is
     * malformed. Tampering with any other field, including an extra field inside the certificate, still breaks the
     * signature.
     */
    @Test
    void entryKeyReplyCertNotAfterJudgedByValue() throws Exception {
        long notAfter = 1_798_761_600_000L;
        KeyPair entry = Crypto.generateEd25519KeyPair();
        Map<String, String> ring = Map.of("pay", key(entry));
        KeyringFile signedRing = KeyringFile.sign(ring, serverKey, NOT_AFTER, serverPolicy.getPrivate());
        ReplyCert cert = ReplyCert.issue(serverKey, "pay", key(entry), notAfter, serverPolicy.getPrivate());
        SessionRequest req = request(clientRoot);
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), nonce, clientKey,
                clientRing);
        SessionReply signed = Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, signedRing.sig(),
                NOT_AFTER, cert, nonce, sess, "attested", List.of(), null), entry.getPrivate());
        String text = signed.toJson();
        String digits = "\"notAfter\":" + notAfter;
        assertTrue(text.contains(digits));

        assertEquals(ReplyCheck.ATTESTED, check(JSON.readTree(text), req, serverKey, "pay", NOW));
        for (String same : List.of("1798761600000.0", "1.7987616e12", "1.7987616E+12")) {
            JsonNode rewritten = JSON.readTree(text.replace(digits, "\"notAfter\":" + same));
            assertEquals(ReplyCheck.ATTESTED, check(rewritten, req, serverKey, "pay", NOW), same);
        }
        JsonNode fraction = JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.5"));
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(fraction, req, serverKey, "pay", NOW));

        ObjectNode otherField = (ObjectNode) JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.0"));
        otherField.put("nonce", Sessions.newNonce());
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(otherField, req, serverKey, "pay", NOW));
        ObjectNode extraInCert = (ObjectNode) JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.0"));
        ((ObjectNode) extraInCert.get("serverReplyCert")).put("note", "added");
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(extraInCert, req, serverKey, "pay", NOW));
    }

    @Test
    void sessionRequestParseRefusesMalformedFields() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> parse(JSON.readTree("[]")));
        ObjectNode ok = tree(request(clientRoot).toJson());
        for (String[] bad : new String[][] {{"clientRoot", "5"}, {"clientKeyring", "{\"a\":1}"}, {"nonce", "7"}}) {
            ObjectNode o = ok.deepCopy();
            o.set(bad[0], JSON.readTree(bad[1]));
            assertThrows(IllegalArgumentException.class, () -> parse(o), bad[0]);
        }
    }

    /**
     * A client root keeps its {@code notAfter} through the request's wire form, so its signature still
     * verifies on the server and the session is attested. Rebuilt from three fields, it would fail and go unsafe.
     */
    @Test
    void aClientRootSurvivesParsing() {
        SessionRequest parsed = SessionRequest.parse(request(clientRoot).toJson());

        assertEquals(clientRoot, parsed.clientRoot());
        assertEquals("attested", status(parsed));
    }

    /**
     * A {@code clientKeyringNotAfter} or client root {@code notAfter} that is missing or not a safe integer in
     * [0, 2^53 &minus; 1] is a shape error, so the request opens no session.
     */
    @Test
    void malformedNotAfterOpensNoSession() throws Exception {
        ObjectNode ok = tree(request(clientRoot).toJson());
        for (String bad : new String[] {"1.5", "\"x\"", "-1", String.valueOf(MAX_SAFE + 1), "null", "true", "{}",
                "[]"}) {
            ObjectNode ring = ok.deepCopy();
            ring.set("clientKeyringNotAfter", JSON.readTree(bad));
            assertThrows(IllegalArgumentException.class, () -> parse(ring), "keyring " + bad);
            ObjectNode root = ok.deepCopy();
            ((ObjectNode) root.get("clientRoot")).set("notAfter", JSON.readTree(bad));
            assertThrows(IllegalArgumentException.class, () -> parse(root), "root " + bad);
        }
        ObjectNode noRing = ok.deepCopy();
        noRing.remove("clientKeyringNotAfter");
        assertThrows(IllegalArgumentException.class, () -> parse(noRing), "keyring missing");
        ObjectNode noRoot = ok.deepCopy();
        ((ObjectNode) noRoot.get("clientRoot")).remove("notAfter");
        assertThrows(IllegalArgumentException.class, () -> parse(noRoot), "root missing");
    }

    /**
     * The client keyring's signature is checked over its {@code clientKeyringNotAfter}. Forged: the window moved by
     * a millisecond fails the signature and the session is unsafe. The same integer written {@code 1.83e12} is the
     * same window, read by value.
     */
    @Test
    void clientKeyringNotAfterIsCoveredByTheKeyringSignature() throws Exception {
        ObjectNode wire = tree(request(clientRoot).toJson());
        assertEquals(NOT_AFTER, wire.get("clientKeyringNotAfter").longValue());
        assertEquals("attested", status(parse(wire)));

        ObjectNode moved = wire.deepCopy();
        moved.put("clientKeyringNotAfter", NOT_AFTER + 1);
        assertEquals("unsafe", status(parse(moved)), "moved");
        ObjectNode byValue = (ObjectNode) JSON.readTree(JSON.writeValueAsString(wire)
                .replace("\"clientKeyringNotAfter\":" + NOT_AFTER, "\"clientKeyringNotAfter\":1.8302976e12"));
        assertEquals("attested", status(parse(byValue)), "by value");
    }

    /**
     * {@code clientKeyringNotAfter} is written with every request and a root's {@code notAfter} inside the root
     * object; {@code serverKeyringNotAfter} only beside the entry-key form's keyring signature. The session id binds
     * root signatures and keyring services, not the keyring's signature or window.
     */
    @Test
    void notAfterIsWrittenWithEveryRootAndKeyring() {
        ObjectNode fresh = tree(request(clientRoot).toJson());
        assertEquals(NOT_AFTER, fresh.get("clientKeyringNotAfter").longValue());
        assertEquals(NOT_AFTER, fresh.get("clientRoot").get("notAfter").longValue());
        assertFalse(wire(reply(request(clientRoot), serverRoot, "attested")).has("serverKeyringNotAfter"));

        // The same root and nonce with the keyring signed until two windows, each as the server parses it off the
        // wire: the two differ in the keyring's signature and window, and in nothing the session id binds.
        KeyringFile laterRing = KeyringFile.sign(clientRing, clientKey, NOT_AFTER + 1, clientPolicy.getPrivate());
        String cn = Sessions.newNonce();
        SessionRequest one = SessionRequest.parse(
                SessionRequest.of(clientRoot, clientKey, clientKeyring, cn).toJson());
        SessionRequest other = SessionRequest.parse(SessionRequest.of(clientRoot, clientKey, laterRing, cn).toJson());
        assertNotEquals(one.clientKeyringSig(), other.clientKeyringSig());
        assertEquals(NOT_AFTER + 1, other.clientKeyringNotAfter());
        String sn = Sessions.newNonce();
        assertEquals(sessionId(one, sn), sessionId(other, sn));
        assertEquals(ReplyCheck.ATTESTED, check(wire(reply(one, serverRoot, "attested")), other, serverKey, "pay",
                NOW), "a reply to one is a reply to the other");
    }

    /** The session id the server derives for {@code req} with its own root and nonce {@code serverNonce}. */
    private String sessionId(SessionRequest req, String serverNonce) {
        return Sessions.deriveSessionId(req.clientRoot().sig(), serverRoot.sig(), req.nonce(), serverNonce,
                req.clientPolicyKey(), req.clientKeyring());
    }

    /**
     * The client's root and keyring are each current up to and including their {@code notAfter} and not a millisecond
     * after; past either, the session is unsafe. Forged: an expired root with its {@code notAfter} moved past now
     * reads as current, so only the root's own signature can refuse it, and does; an expired keyring with its
     * {@code clientKeyringNotAfter} moved is refused by the keyring signature.
     */
    @Test
    void anExpiredClientRootOrKeyringIsUnsafe() {
        byte[] rootBytes = Crypto.sha256("c".getBytes());
        SignedRoot untilNow = SignedRoot.sign(rootBytes, "v1", NOW, clientPolicy.getPrivate());
        KeyringFile ringUntilNow = KeyringFile.sign(clientRing, clientKey, NOW, clientPolicy.getPrivate());
        SessionRequest rootReq = SessionRequest.of(untilNow, clientKey, clientKeyring, Sessions.newNonce());
        SessionRequest ringReq = SessionRequest.of(clientRoot, clientKey, ringUntilNow, Sessions.newNonce());
        PublicKey own = serverPolicy.getPublic();
        Set<String> pinned = Set.of(clientKey);
        assertEquals("attested", status(rootReq), "root at notAfter");
        assertEquals("unsafe", Sessions.status(rootReq, serverRoot, serverKeyring, own, pinned, NOW + 1), "root past");
        assertEquals("attested", status(ringReq), "keyring at notAfter");
        assertEquals("unsafe", Sessions.status(ringReq, serverRoot, serverKeyring, own, pinned, NOW + 1),
                "keyring past");

        SignedRoot expired = SignedRoot.sign(rootBytes, "v1", NOW - 1, clientPolicy.getPrivate());
        SignedRoot moved = new SignedRoot(expired.rootId(), expired.root(), expired.sig(), NOT_AFTER);
        assertTrue(moved.isCurrent(NOW));
        assertFalse(moved.verify(clientPolicy.getPublic()));
        assertEquals("unsafe", status(SessionRequest.parse(
                SessionRequest.of(moved, clientKey, clientKeyring, Sessions.newNonce()).toJson())), "root moved");

        KeyringFile expiredRing = KeyringFile.sign(clientRing, clientKey, NOW - 1, clientPolicy.getPrivate());
        ObjectNode ringMoved = tree(
                SessionRequest.of(clientRoot, clientKey, expiredRing, Sessions.newNonce()).toJson());
        ringMoved.put("clientKeyringNotAfter", NOT_AFTER);
        assertEquals("unsafe", status(parse(ringMoved)), "keyring moved");
    }

    /**
     * A server whose own root or keyring is past its {@code notAfter} opens every session unsafe, however
     * good the client's material: it degrades to serving unattested callers rather than stopping. A missing keyring
     * is unsafe too.
     */
    @Test
    void aServerWhoseOwnRootOrKeyringIsNotCurrentOpensEverySessionUnsafe() {
        SessionRequest req = request(clientRoot);
        PublicKey own = serverPolicy.getPublic();
        Set<String> pinned = Set.of(clientKey);
        byte[] rootBytes = Crypto.sha256("s".getBytes());
        SignedRoot rootUntilNow = SignedRoot.sign(rootBytes, "v1", NOW, serverPolicy.getPrivate());
        KeyringFile ringUntilNow = KeyringFile.sign(serverKeyring.services(), serverKey, NOW,
                serverPolicy.getPrivate());
        assertEquals("attested", Sessions.status(req, rootUntilNow, ringUntilNow, own, pinned, NOW));
        assertEquals("unsafe", Sessions.status(req, rootUntilNow, serverKeyring, own, pinned, NOW + 1), "root past");
        assertEquals("unsafe", Sessions.status(req, serverRoot, ringUntilNow, own, pinned, NOW + 1), "keyring past");
        assertEquals("unsafe", Sessions.status(req, serverRoot, null, own, pinned, NOW), "no keyring");
    }

    /**
     * The client judges the server's root in either reply form and either status, and in the entry-key form its
     * keyring: each current up to and including its {@code notAfter}, {@code BAD_SIGNATURE} a millisecond after, so
     * the client takes its replacement path. Forged: an expired root with its window moved past now, the reply signed
     * again by the entry key so its own signature holds; only the root's signature refuses it. A
     * {@code serverKeyringNotAfter} in a policy-key reply is a keyring window with no keyring signature, refused as
     * either form field without the other is. A server root without its {@code notAfter}, or an entry-key reply
     * without {@code serverKeyringNotAfter}, is malformed.
     */
    @Test
    void theServersRootAndKeyringAreJudgedInTheReply() {
        SessionRequest req = request(clientRoot);
        byte[] rootBytes = Crypto.sha256("s".getBytes());
        SignedRoot rootUntilNow = SignedRoot.sign(rootBytes, "v1", NOW, serverPolicy.getPrivate());
        JsonNode policyForm = wire(reply(req, rootUntilNow, "attested"));
        assertEquals(ReplyCheck.ATTESTED, check(policyForm, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(policyForm, req, serverKey, "pay", NOW + 1));
        JsonNode unsafe = wire(reply(req, rootUntilNow, "unsafe"));
        assertEquals(ReplyCheck.UNSAFE, check(unsafe, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(unsafe, req, serverKey, "pay", NOW + 1));

        KeyPair entry = Crypto.generateEd25519KeyPair();
        long certNotAfter = NOW + 1000;
        assertEquals(ReplyCheck.ATTESTED, check(entryKeyReply(req, entry, certNotAfter, rootUntilNow,
                NOT_AFTER), req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(entryKeyReply(req, entry, certNotAfter,
                rootUntilNow, NOT_AFTER), req, serverKey, "pay", NOW + 1), "root past, entry-key form");
        JsonNode ringUntilNow = entryKeyReply(req, entry, certNotAfter, serverRoot, NOW);
        assertEquals(ReplyCheck.ATTESTED, check(ringUntilNow, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(ringUntilNow, req, serverKey, "pay", NOW + 1),
                "keyring past");

        SignedRoot expired = SignedRoot.sign(rootBytes, "v1", NOW - 1, serverPolicy.getPrivate());
        SignedRoot extended = new SignedRoot(expired.rootId(), expired.root(), expired.sig(), NOT_AFTER);
        assertTrue(extended.isCurrent(NOW));
        assertFalse(extended.verify(serverPolicy.getPublic()));
        JsonNode byEntry = entryKeyReply(req, entry, certNotAfter, extended, NOT_AFTER);
        assertEquals(NOT_AFTER, byEntry.get("serverRoot").get("notAfter").longValue());
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "pay", NOW));

        String pn = Sessions.newNonce();
        String ps = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), pn, clientKey,
                clientRing);
        Map<String, String> ring = Map.of("pay", "server-key");
        JsonNode withoutWindow = wire(Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, null, null,
                null, pn, ps, "attested", List.of(), null), serverPolicy.getPrivate()));
        assertEquals(ReplyCheck.ATTESTED, check(withoutWindow, req, serverKey, "pay", NOW));
        JsonNode withWindow = wire(Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, null, NOT_AFTER,
                null, pn, ps, "attested", List.of(), null), serverPolicy.getPrivate()));
        assertTrue(withWindow.has("serverKeyringNotAfter"));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(withWindow, req, serverKey, "pay", NOW));

        ObjectNode rootWindowDropped = (ObjectNode) policyForm.deepCopy();
        ((ObjectNode) rootWindowDropped.get("serverRoot")).remove("notAfter");
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(rootWindowDropped, req, serverKey, "pay", NOW));
        ObjectNode ringWindowDropped = (ObjectNode) entryKeyReply(req, entry, certNotAfter, serverRoot, NOT_AFTER)
                .deepCopy();
        ringWindowDropped.remove("serverKeyringNotAfter");
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(ringWindowDropped, req, serverKey, "pay", NOW));
    }

    /** An entry-key reply: server root and keyring, the keyring's window beside it as on the request. */
    private JsonNode entryKeyReply(SessionRequest req, KeyPair entry, long certNotAfter) {
        return entryKeyReply(req, entry, certNotAfter, serverRoot, NOT_AFTER);
    }

    /** An entry-key reply carrying {@code root} and a keyring signed until {@code ringNotAfter}. */
    private JsonNode entryKeyReply(SessionRequest req, KeyPair entry, long certNotAfter, SignedRoot root,
            long ringNotAfter) {
        Map<String, String> ring = Map.of("pay", key(entry));
        KeyringFile signedRing = KeyringFile.sign(ring, serverKey, ringNotAfter, serverPolicy.getPrivate());
        ReplyCert cert = ReplyCert.issue(serverKey, "pay", key(entry), certNotAfter, serverPolicy.getPrivate());
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), root.sig(), req.nonce(), nonce, clientKey,
                clientRing);
        return wire(Sessions.signReply(new SessionReply(root, serverKey, ring, signedRing.sig(), ringNotAfter, cert,
                nonce, sess, "attested", List.of(), null), entry.getPrivate()));
    }

    /**
     * A reply's {@code serverKeyringNotAfter} and its root's {@code notAfter} are carried and checked. Forged: either
     * moved by a millisecond fails the signature; one dropped, or a value that is not a safe integer in
     * [0, 2^53 &minus; 1], is malformed. Written {@code 1.8302976e12}, each is the same integer, and since the reply's
     * signature covers its parsed value, the verdict is the plain digits' one, as in TypeScript.
     */
    @Test
    void replyNotAftersAreCarriedAndChecked() throws Exception {
        SessionRequest req = request(clientRoot);
        JsonNode reply = entryKeyReply(req, Crypto.generateEd25519KeyPair(), NOW + 1000);
        assertEquals(NOT_AFTER, reply.get("serverKeyringNotAfter").longValue());
        assertEquals(NOT_AFTER, reply.get("serverRoot").get("notAfter").longValue());
        assertEquals(ReplyCheck.ATTESTED, check(reply, req, serverKey, "pay", NOW));

        ObjectNode ringMoved = reply.deepCopy();
        ringMoved.put("serverKeyringNotAfter", NOT_AFTER + 1);
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(ringMoved, req, serverKey, "pay", NOW));
        ObjectNode ringDropped = reply.deepCopy();
        ringDropped.remove("serverKeyringNotAfter");
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(ringDropped, req, serverKey, "pay", NOW));
        ObjectNode rootMoved = reply.deepCopy();
        ((ObjectNode) rootMoved.get("serverRoot")).put("notAfter", NOT_AFTER + 1);
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(rootMoved, req, serverKey, "pay", NOW));

        for (String bad : new String[] {"1.5", "\"x\"", "-1", String.valueOf(MAX_SAFE + 1), "null", "true", "{}",
                "[]"}) {
            ObjectNode ring = reply.deepCopy();
            ring.set("serverKeyringNotAfter", JSON.readTree(bad));
            assertEquals(ReplyCheck.MALFORMED_REPLY, check(ring, req, serverKey, "pay", NOW), bad);
            ObjectNode root = reply.deepCopy();
            ((ObjectNode) root.get("serverRoot")).set("notAfter", JSON.readTree(bad));
            assertEquals(ReplyCheck.MALFORMED_REPLY, check(root, req, serverKey, "pay", NOW), bad);
        }

        String text = JSON.writeValueAsString(reply);
        assertEquals(2, text.split("otAfter\":" + NOT_AFTER, -1).length - 1);
        JsonNode byValue = JSON.readTree(text.replace("otAfter\":" + NOT_AFTER, "otAfter\":1.8302976e12"));
        assertEquals(ReplyCheck.ATTESTED, check(byValue, req, serverKey, "pay", NOW));
    }

    @Test
    void opensSessionFalse() {
        SessionRequest ok = request(clientRoot);
        assertTrue(Sessions.opensSession(ok));
        SessionRequest shortNonce = new SessionRequest(clientRoot, clientKey, clientRing, ok.clientKeyringSig(),
                NOT_AFTER, Base64Url.encode(new byte[15]));
        assertFalse(Sessions.opensSession(shortNonce));
        SessionRequest shortSig = new SessionRequest(
                new SignedRoot("v1", clientRoot.root(), Base64Url.encode(new byte[63]), NOT_AFTER), clientKey,
                clientRing, ok.clientKeyringSig(), NOT_AFTER, ok.nonce());
        assertFalse(Sessions.opensSession(shortSig));
    }
}
