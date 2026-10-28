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
    private static final long NOW = 1_767_225_600_000L;
    /** The new-form roots' and keyrings' window, 2028-01-01: unlike any certificate's, so a test can rewrite one. */
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

    private static String key(KeyPair pair) {
        return Base64Url.encode(Crypto.encodePublicKey(pair.getPublic()));
    }

    private SessionRequest request(SignedRoot root) {
        return SessionRequest.of(root, clientKey, clientKeyring, Sessions.newNonce());
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
        return JSON.valueToTree(r.toJson());
    }

    @Test
    void attestedRoundTrip() {
        SessionRequest req = request(clientRoot);
        assertEquals("attested", Sessions.status(req, serverRoot, serverPolicy.getPublic(), Set.of(clientKey)));
        assertTrue(Sessions.opensSession(req));

        SessionReply reply = reply(req, serverRoot, "attested");
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(wire(reply), req, serverKey, "pay", NOW));
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
                Base64Url.encode(new byte[64]), NOT_AFTER, good.nonce());
        assertEquals("unsafe", Sessions.status(wrongSig, serverRoot, own, pinned), "wrong keyring sig");
        SessionRequest legacy = new SessionRequest(clientRoot, clientKey, clientRing, null, null, good.nonce());
        assertTrue(legacy.legacy());
        assertEquals("unsafe", Sessions.status(legacy, serverRoot, own, pinned), "legacy");
        assertEquals("unsafe", Sessions.status(good, null, own, pinned), "no server root");
        assertEquals("attested", Sessions.status(good, serverRoot, own, pinned));
    }

    @Test
    void checkReplyOutcomes() {
        SessionRequest req = request(clientRoot);
        SessionReply attested = reply(req, serverRoot, "attested");

        assertEquals(ReplyCheck.MALFORMED_REPLY,
                Sessions.checkReply(JSON.valueToTree("nope"), req, serverKey, "pay", NOW));
        ObjectNode noStatus = (ObjectNode) wire(attested);
        noStatus.remove("status");
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(noStatus, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.PIN_MISMATCH, Sessions.checkReply(wire(attested), req, key(clientPolicy), "pay", NOW));

        ObjectNode altered = (ObjectNode) wire(attested);
        altered.put("nonce", Sessions.newNonce());
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(altered, req, serverKey, "pay", NOW));

        SessionReply nullRoot = reply(req, null, "attested");
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(wire(nullRoot), req, serverKey, "pay", NOW));

        SessionReply unsafe = reply(req, serverRoot, "unsafe");
        assertEquals(ReplyCheck.UNSAFE, Sessions.checkReply(wire(unsafe), req, serverKey, "pay", NOW));
        assertNotNull(unsafe.sig());
    }

    /**
     * The entry-key form: signed by the entry service's key, which the reply's signed keyring and certificate
     * vouch for. The forged cases: an expired certificate, an entry the client did not configure, the same reply
     * signed by the policy key (the form is decided by the fields, so the pin is never tried), and a certificate
     * the record drops (the policy-key form then needs the policy key, which did not sign it).
     */
    @Test
    void entryKeyForm() {
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
        assertEquals(cert.toJson(), byEntry.get("serverReplyCert"));
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(byEntry, req, serverKey, "pay", NOW + 1000));
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(byEntry, req, serverKey, "pay", NOW + 1001));
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(byEntry, req, serverKey, "ledger", NOW));

        JsonNode byPolicy = wire(Sessions.signReply(unsigned, serverPolicy.getPrivate()));
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(byPolicy, req, serverKey, "pay", NOW));

        ObjectNode noCert = (ObjectNode) byEntry.deepCopy();
        noCert.remove("serverReplyCert");
        noCert.remove("serverKeyringSig");
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(noCert, req, serverKey, "pay", NOW));
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
        String text = JSON.writeValueAsString(signed.toJson());
        String digits = "\"notAfter\":" + notAfter;
        assertTrue(text.contains(digits));

        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(JSON.readTree(text), req, serverKey, "pay", NOW));
        for (String same : List.of("1798761600000.0", "1.7987616e12", "1.7987616E+12")) {
            JsonNode rewritten = JSON.readTree(text.replace(digits, "\"notAfter\":" + same));
            assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(rewritten, req, serverKey, "pay", NOW), same);
        }
        JsonNode fraction = JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.5"));
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(fraction, req, serverKey, "pay", NOW));

        ObjectNode otherField = (ObjectNode) JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.0"));
        otherField.put("nonce", Sessions.newNonce());
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(otherField, req, serverKey, "pay", NOW));
        ObjectNode extraInCert = (ObjectNode) JSON.readTree(text.replace(digits, "\"notAfter\":1798761600000.0"));
        ((ObjectNode) extraInCert.get("serverReplyCert")).put("note", "added");
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(extraInCert, req, serverKey, "pay", NOW));
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

    /**
     * A new-form client root keeps its {@code notAfter} through the request's wire form, so its signature still
     * verifies on the server and the session is attested. Rebuilt from three fields, it would fail and go unsafe.
     */
    @Test
    void newFormClientRootSurvivesParsing() {
        SessionRequest parsed = Sessions.parseRequest(request(clientRoot).toJson());

        assertEquals(clientRoot, parsed.clientRoot());
        assertEquals("attested", Sessions.status(parsed, serverRoot, serverPolicy.getPublic(), Set.of(clientKey)));
    }

    /**
     * A present {@code clientKeyringNotAfter} or client root {@code notAfter} that is not a safe integer in
     * [0, 2^53 &minus; 1] is a shape error, so the request opens no session; it is never read as absent, which would
     * turn a damaged window into the old form.
     */
    @Test
    void malformedNotAfterOpensNoSession() throws Exception {
        ObjectNode ok = request(clientRoot).toJson();
        for (String bad : new String[] {"1.5", "\"x\"", "-1", String.valueOf(MAX_SAFE + 1), "null", "true", "{}",
                "[]"}) {
            ObjectNode ring = ok.deepCopy();
            ring.set("clientKeyringNotAfter", JSON.readTree(bad));
            assertThrows(IllegalArgumentException.class, () -> Sessions.parseRequest(ring), "keyring " + bad);
            ObjectNode root = ok.deepCopy();
            ((ObjectNode) root.get("clientRoot")).set("notAfter", JSON.readTree(bad));
            assertThrows(IllegalArgumentException.class, () -> Sessions.parseRequest(root), "root " + bad);
        }
    }

    /**
     * The client keyring's signature is checked over the bytes its {@code clientKeyringNotAfter} selects. Forged:
     * the window moved by a millisecond, or dropped so the keyring reads as the old form; either way the signature
     * fails and the session is unsafe. The same integer written {@code 1.83e12} is the same window, read by value.
     */
    @Test
    void clientKeyringNotAfterIsCoveredByTheKeyringSignature() throws Exception {
        Set<String> pinned = Set.of(clientKey);
        PublicKey own = serverPolicy.getPublic();
        ObjectNode wire = request(clientRoot).toJson();
        assertEquals(NOT_AFTER, wire.get("clientKeyringNotAfter").longValue());
        assertEquals("attested", Sessions.status(Sessions.parseRequest(wire), serverRoot, own, pinned));

        ObjectNode moved = wire.deepCopy();
        moved.put("clientKeyringNotAfter", NOT_AFTER + 1);
        assertEquals("unsafe", Sessions.status(Sessions.parseRequest(moved), serverRoot, own, pinned), "moved");
        ObjectNode dropped = wire.deepCopy();
        dropped.remove("clientKeyringNotAfter");
        assertEquals("unsafe", Sessions.status(Sessions.parseRequest(dropped), serverRoot, own, pinned), "dropped");
        ObjectNode byValue = (ObjectNode) JSON.readTree(JSON.writeValueAsString(wire)
                .replace("\"clientKeyringNotAfter\":" + NOT_AFTER, "\"clientKeyringNotAfter\":1.8302976e12"));
        assertEquals("attested", Sessions.status(Sessions.parseRequest(byValue), serverRoot, own, pinned), "by value");
    }

    /**
     * {@code clientKeyringNotAfter} and {@code serverKeyringNotAfter} are written only for a new-form keyring, and a
     * root's {@code notAfter} only for a new-form root, inside the root object. The session id is the same for
     * either form: it binds root signatures and keyring services, not the keyring's signature or window.
     */
    @Test
    void notAfterIsWrittenOnlyForTheNewForm() {
        KeyringFile oldRing = KeyringFile.signOldForm(clientRing, clientKey, clientPolicy.getPrivate());
        SignedRoot oldRoot = SignedRoot.signOldForm(Crypto.sha256("c".getBytes()), "v1", clientPolicy.getPrivate());
        ObjectNode old = SessionRequest.of(oldRoot, clientKey, oldRing, Sessions.newNonce()).toJson();
        assertFalse(old.has("clientKeyringNotAfter"));
        assertFalse(old.get("clientRoot").has("notAfter"));
        ObjectNode fresh = request(clientRoot).toJson();
        assertEquals(NOT_AFTER, fresh.get("clientRoot").get("notAfter").longValue());
        assertFalse(wire(reply(request(clientRoot), serverRoot, "attested")).has("serverKeyringNotAfter"));

        String sn = Sessions.newNonce();
        String cn = Sessions.newNonce();
        assertEquals(Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), cn, sn, clientKey, clientRing),
                Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), cn, sn, clientKey,
                        oldRing.services()));
    }

    /** Old-form material still verifies, in either message: the form decides only which bytes are checked. */
    @Test
    void oldFormMaterialStillVerifies() {
        KeyringFile oldRing = KeyringFile.signOldForm(clientRing, clientKey, clientPolicy.getPrivate());
        SignedRoot oldRoot = SignedRoot.signOldForm(Crypto.sha256("c".getBytes()), "v1", clientPolicy.getPrivate());
        SessionRequest req = Sessions.parseRequest(
                SessionRequest.of(oldRoot, clientKey, oldRing, Sessions.newNonce()).toJson());
        assertEquals("attested", Sessions.status(req, serverRoot, serverPolicy.getPublic(), Set.of(clientKey)));
        SignedRoot oldServer = SignedRoot.signOldForm(Crypto.sha256("s".getBytes()), "v1", serverPolicy.getPrivate());
        assertEquals(ReplyCheck.ATTESTED,
                Sessions.checkReply(wire(reply(req, oldServer, "attested")), req, serverKey, "pay", NOW));
    }

    /** An entry-key reply: new-form server root and keyring, the keyring's window beside it as on the request. */
    private JsonNode entryKeyReply(SessionRequest req, KeyPair entry, long certNotAfter) {
        Map<String, String> ring = Map.of("pay", key(entry));
        KeyringFile signedRing = KeyringFile.sign(ring, serverKey, NOT_AFTER, serverPolicy.getPrivate());
        ReplyCert cert = ReplyCert.issue(serverKey, "pay", key(entry), certNotAfter, serverPolicy.getPrivate());
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), nonce, clientKey,
                clientRing);
        return wire(Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, signedRing.sig(), NOT_AFTER, cert,
                nonce, sess, "attested", List.of(), null), entry.getPrivate()));
    }

    /**
     * A reply's {@code serverKeyringNotAfter} and its root's {@code notAfter} are carried and checked. Forged: either
     * moved by a millisecond, or the keyring's dropped, fails the signature; a value that is not a safe integer in
     * [0, 2^53 &minus; 1] is malformed. Written {@code 1.8302976e12}, each is the same integer, and since the reply's
     * signature covers its parsed value, the verdict is the plain digits' one, as in TypeScript.
     */
    @Test
    void replyNotAftersAreCarriedAndChecked() throws Exception {
        SessionRequest req = request(clientRoot);
        JsonNode reply = entryKeyReply(req, Crypto.generateEd25519KeyPair(), NOW + 1000);
        assertEquals(NOT_AFTER, reply.get("serverKeyringNotAfter").longValue());
        assertEquals(NOT_AFTER, reply.get("serverRoot").get("notAfter").longValue());
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(reply, req, serverKey, "pay", NOW));

        ObjectNode ringMoved = reply.deepCopy();
        ringMoved.put("serverKeyringNotAfter", NOT_AFTER + 1);
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(ringMoved, req, serverKey, "pay", NOW));
        ObjectNode ringDropped = reply.deepCopy();
        ringDropped.remove("serverKeyringNotAfter");
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(ringDropped, req, serverKey, "pay", NOW));
        ObjectNode rootMoved = reply.deepCopy();
        ((ObjectNode) rootMoved.get("serverRoot")).put("notAfter", NOT_AFTER + 1);
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(rootMoved, req, serverKey, "pay", NOW));

        for (String bad : new String[] {"1.5", "\"x\"", "-1", String.valueOf(MAX_SAFE + 1), "null", "true", "{}",
                "[]"}) {
            ObjectNode ring = reply.deepCopy();
            ring.set("serverKeyringNotAfter", JSON.readTree(bad));
            assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(ring, req, serverKey, "pay", NOW), bad);
            ObjectNode root = reply.deepCopy();
            ((ObjectNode) root.get("serverRoot")).set("notAfter", JSON.readTree(bad));
            assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(root, req, serverKey, "pay", NOW), bad);
        }

        String text = JSON.writeValueAsString(reply);
        assertEquals(2, text.split("otAfter\":" + NOT_AFTER, -1).length - 1);
        JsonNode byValue = JSON.readTree(text.replace("otAfter\":" + NOT_AFTER, "otAfter\":1.8302976e12"));
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(byValue, req, serverKey, "pay", NOW));
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
