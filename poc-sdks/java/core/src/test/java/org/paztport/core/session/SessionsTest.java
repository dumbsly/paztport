// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import org.paztport.core.policy.SignedRoot;

class SessionsTest {

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

    /** A message's JSON value, read from its wire text as the SDK reads it, so a test can alter it. */
    private static JsonValue.Obj tree(String json) {
        return (JsonValue.Obj) JsonReader.wireText(json);
    }

    private static JsonValue.Obj wire(SessionReply r) {
        return tree(r.toJson());
    }

    /** {@code o} with its member {@code name} set to {@code value}, added or replaced. */
    private static JsonValue.Obj with(JsonValue.Obj o, String name, JsonValue value) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.put(name, value);
        return new JsonValue.Obj(members);
    }

    /** {@code o} without its member {@code name}. */
    private static JsonValue.Obj without(JsonValue.Obj o, String name) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.remove(name);
        return new JsonValue.Obj(members);
    }

    private static JsonValue.Obj member(JsonValue.Obj o, String name) {
        return (JsonValue.Obj) o.get(name);
    }

    /** The values of other types a member that must be an integer is given. */
    private static final List<JsonValue> NOT_INTEGERS = List.of(new JsonValue.Str("x"), new JsonValue.Null(),
            new JsonValue.Bool(true), new JsonValue.Obj(Map.of()), new JsonValue.Arr(List.of()));

    /** The numbers no reader reads, each in place of {@link #NOT_AFTER}'s digits. */
    private static final List<String> NOT_PROTOCOL_INTEGERS =
            List.of("1.5", "-1", String.valueOf(MAX_SAFE + 1), NOT_AFTER + ".0", "1.8302976e12");

    /** {@code o}'s JCS text, signed again with {@code key} as a reply is: over every member but {@code sig}. */
    private static String signed(JsonValue.Obj o, PrivateKey key) {
        JsonValue.Obj body = without(o, "sig");
        byte[] prefix = "paztport-session-reply\n".getBytes(StandardCharsets.UTF_8);
        byte[] json = JsonWriter.wire(body);
        byte[] bytes = new byte[prefix.length + json.length];
        System.arraycopy(prefix, 0, bytes, 0, prefix.length);
        System.arraycopy(json, 0, bytes, prefix.length, json.length);
        return JsonWriter.text(with(body, "sig", new JsonValue.Str(Base64Url.encode(Crypto.sign(key, bytes)))));
    }

    /** The client's check of a reply held as a value, so a test can alter it first. */
    private static ReplyCheck check(JsonValue reply, SessionRequest req, String pin, String entry, long now) {
        return Sessions.checkReply(JsonWriter.text(reply), req, pin, entry, now);
    }

    private static SessionRequest parse(JsonValue request) {
        return SessionRequest.parse(JsonWriter.text(request));
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

        assertEquals(ReplyCheck.MALFORMED_REPLY, check(new JsonValue.Str("nope"), req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(without(wire(attested), "status"), req, serverKey, "pay",
                NOW));
        assertEquals(ReplyCheck.PIN_MISMATCH, check(wire(attested), req, key(clientPolicy), "pay", NOW));

        JsonValue.Obj altered = with(wire(attested), "nonce", new JsonValue.Str(Sessions.newNonce()));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(altered, req, serverKey, "pay", NOW));

        SessionReply nullRoot = reply(req, null, "attested");
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(wire(nullRoot), req, serverKey, "pay", NOW));

        SessionReply unsafe = reply(req, serverRoot, "unsafe");
        assertEquals(ReplyCheck.UNSAFE, check(wire(unsafe), req, serverKey, "pay", NOW));
        assertNotNull(unsafe.sig());
    }

    /**
     * A reply is read from its bytes as wire bytes: the same reply in another member order, or with a newline after
     * it, is not its canonical bytes, and is malformed before its signature is looked at.
     */
    @Test
    void aReplyThatIsNotItsCanonicalBytesIsMalformed() {
        SessionRequest req = request(clientRoot);
        String text = reply(req, serverRoot, "attested").toJson();
        int sig = text.lastIndexOf(",\"sig\":");
        String sigFirst = "{" + text.substring(sig + 1, text.length() - 1) + "," + text.substring(1, sig) + "}";

        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(text, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(sigFirst, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(text + "\n", req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.MALFORMED_REPLY,
                Sessions.checkReply((text + "\n").getBytes(StandardCharsets.UTF_8), req, serverKey, "pay", NOW));
    }

    /** A keyring names its services by route nodes wherever it is read: the client's in a request, the server's in a reply. */
    @Test
    void aKeyringNameThatIsNotARouteNodeIsMalformed() {
        SessionRequest req = request(clientRoot);
        JsonValue.Obj reply = entryKeyReply(req, Crypto.generateEd25519KeyPair(), NOW + 1000);
        for (String name : new String[] {"", ".", "..", "a/b", "a\\b", "a|b"}) {
            JsonValue.Obj ring = new JsonValue.Obj(Map.of(name, new JsonValue.Str("k")));
            assertEquals("member clientKeyring holds a name that is not a route node",
                    assertThrows(IllegalArgumentException.class,
                            () -> parse(with(tree(req.toJson()), "clientKeyring", ring)), name).getMessage());
            assertEquals(ReplyCheck.MALFORMED_REPLY,
                    Sessions.checkReply(JsonWriter.text(with(reply, "serverKeyring", ring)), req, serverKey, "pay",
                            NOW), name);
        }
    }

    /**
     * A reply has exactly its members, so one the server signed with a member a reply does not have is malformed,
     * and so is a certificate in it with a member a certificate does not have.
     */
    @Test
    void aReplyWithAnExtraMemberIsMalformed() {
        SessionRequest req = request(clientRoot);
        KeyPair entry = Crypto.generateEd25519KeyPair();
        JsonValue.Obj reply = entryKeyReply(req, entry, NOW + 1000);
        assertEquals(ReplyCheck.ATTESTED, check(tree(signed(reply, entry.getPrivate())), req, serverKey, "pay", NOW));

        String extra = signed(with(reply, "serverEntry", new JsonValue.Str("pay")), entry.getPrivate());
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(extra, req, serverKey, "pay", NOW));
        String extraInCert = signed(with(reply, "serverReplyCert",
                with(member(reply, "serverReplyCert"), "note", new JsonValue.Str("added"))), entry.getPrivate());
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(extraInCert, req, serverKey, "pay", NOW));
        String extraInRoot = signed(with(reply, "serverRoot",
                with(member(reply, "serverRoot"), "note", new JsonValue.Str("added"))), entry.getPrivate());
        assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(extraInRoot, req, serverKey, "pay", NOW));
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

        JsonValue.Obj byEntry = wire(Sessions.signReply(unsigned, entry.getPrivate()));
        assertEquals(tree(cert.toJson()), byEntry.get("serverReplyCert"));
        assertEquals(ReplyCheck.ATTESTED, check(byEntry, req, serverKey, "pay", NOW + 1000));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "pay", NOW + 1001));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "ledger", NOW));

        JsonValue.Obj byPolicy = wire(Sessions.signReply(unsigned, serverPolicy.getPrivate()));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byPolicy, req, serverKey, "pay", NOW));

        JsonValue.Obj noCert = without(without(byEntry, "serverReplyCert"), "serverKeyringSig");
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(noCert, req, serverKey, "pay", NOW));
    }

    /**
     * A certificate's {@code notAfter} is a protocol integer: written {@code 1798761600000.0} or
     * {@code 1.7987616e12}, or as a fraction, the reply does not read, and is malformed.
     */
    @Test
    void aCertificateNotAfterWrittenAnyOtherWayIsMalformed() {
        long notAfter = 1_798_761_600_000L;
        KeyPair entry = Crypto.generateEd25519KeyPair();
        Map<String, String> ring = Map.of("pay", key(entry));
        KeyringFile signedRing = KeyringFile.sign(ring, serverKey, NOT_AFTER, serverPolicy.getPrivate());
        ReplyCert cert = ReplyCert.issue(serverKey, "pay", key(entry), notAfter, serverPolicy.getPrivate());
        SessionRequest req = request(clientRoot);
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), nonce, clientKey,
                clientRing);
        String text = Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, signedRing.sig(),
                NOT_AFTER, cert, nonce, sess, "attested", List.of(), null), entry.getPrivate()).toJson();
        String digits = "\"notAfter\":" + notAfter;
        assertTrue(text.contains(digits));

        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(text, req, serverKey, "pay", NOW));
        for (String other : List.of("1798761600000.0", "1.7987616e12", "1.7987616E+12", "1798761600000.5")) {
            assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(
                    text.replace(digits, "\"notAfter\":" + other), req, serverKey, "pay", NOW), other);
        }
    }

    @Test
    void sessionRequestParseRefusesMalformedFields() {
        assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse("[]"));
        JsonValue.Obj ok = tree(request(clientRoot).toJson());
        for (JsonValue bad : List.of(new JsonValue.Int(5), new JsonValue.Str("root"))) {
            assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientRoot", bad)), "clientRoot");
        }
        assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientKeyring",
                new JsonValue.Obj(Map.of("a", new JsonValue.Int(1))))), "clientKeyring");
        assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "nonce", new JsonValue.Int(7))), "nonce");
        assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientPolicyKey", new JsonValue.Null())),
                "clientPolicyKey");
    }

    /** A request has exactly its members: one it does not have, at its top or in its root, is malformed. */
    @Test
    void aRequestWithAnExtraMemberIsMalformed() {
        JsonValue.Obj ok = tree(request(clientRoot).toJson());
        assertEquals("a member the object does not define", assertThrows(IllegalArgumentException.class,
                () -> parse(with(ok, "serverEntry", new JsonValue.Str("pay")))).getMessage());
        assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientRoot",
                with(member(ok, "clientRoot"), "note", new JsonValue.Str("added")))));
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
     * A {@code clientKeyringNotAfter} or client root {@code notAfter} that is missing, not an integer, or a number
     * that is not a protocol integer is a shape error, so the request opens no session.
     */
    @Test
    void malformedNotAfterOpensNoSession() {
        JsonValue.Obj ok = tree(request(clientRoot).toJson());
        for (JsonValue bad : NOT_INTEGERS) {
            assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientKeyringNotAfter", bad)),
                    "keyring " + bad);
            assertThrows(IllegalArgumentException.class, () -> parse(with(ok, "clientRoot",
                    with(member(ok, "clientRoot"), "notAfter", bad))), "root " + bad);
        }
        String text = JsonWriter.text(ok);
        assertEquals(2, text.split("otAfter\":" + NOT_AFTER, -1).length - 1);
        for (String bad : NOT_PROTOCOL_INTEGERS) {
            assertThrows(IllegalArgumentException.class,
                    () -> SessionRequest.parse(text.replace("otAfter\":" + NOT_AFTER, "otAfter\":" + bad)), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> parse(without(ok, "clientKeyringNotAfter")),
                "keyring missing");
        assertThrows(IllegalArgumentException.class,
                () -> parse(with(ok, "clientRoot", without(member(ok, "clientRoot"), "notAfter"))), "root missing");
    }

    /**
     * The client keyring's signature is checked over its {@code clientKeyringNotAfter}. Forged: the window moved by
     * a millisecond fails the signature and the session is unsafe.
     */
    @Test
    void clientKeyringNotAfterIsCoveredByTheKeyringSignature() {
        JsonValue.Obj wire = tree(request(clientRoot).toJson());
        assertEquals(new JsonValue.Int(NOT_AFTER), wire.get("clientKeyringNotAfter"));
        assertEquals("attested", status(parse(wire)));

        JsonValue.Obj moved = with(wire, "clientKeyringNotAfter", new JsonValue.Int(NOT_AFTER + 1));
        assertEquals("unsafe", status(parse(moved)), "moved");
    }

    /**
     * {@code clientKeyringNotAfter} is written with every request and a root's {@code notAfter} inside the root
     * object; {@code serverKeyringNotAfter} only beside the entry-key form's keyring signature. The session id binds
     * root signatures and keyring services, not the keyring's signature or window.
     */
    @Test
    void notAfterIsWrittenWithEveryRootAndKeyring() {
        JsonValue.Obj fresh = tree(request(clientRoot).toJson());
        assertEquals(new JsonValue.Int(NOT_AFTER), fresh.get("clientKeyringNotAfter"));
        assertEquals(new JsonValue.Int(NOT_AFTER), member(fresh, "clientRoot").get("notAfter"));
        assertNull(wire(reply(request(clientRoot), serverRoot, "attested")).get("serverKeyringNotAfter"));

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
        JsonValue.Obj ringMoved = with(tree(
                SessionRequest.of(clientRoot, clientKey, expiredRing, Sessions.newNonce()).toJson()),
                "clientKeyringNotAfter", new JsonValue.Int(NOT_AFTER));
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
        JsonValue.Obj policyForm = wire(reply(req, rootUntilNow, "attested"));
        assertEquals(ReplyCheck.ATTESTED, check(policyForm, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(policyForm, req, serverKey, "pay", NOW + 1));
        JsonValue.Obj unsafe = wire(reply(req, rootUntilNow, "unsafe"));
        assertEquals(ReplyCheck.UNSAFE, check(unsafe, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(unsafe, req, serverKey, "pay", NOW + 1));

        KeyPair entry = Crypto.generateEd25519KeyPair();
        long certNotAfter = NOW + 1000;
        assertEquals(ReplyCheck.ATTESTED, check(entryKeyReply(req, entry, certNotAfter, rootUntilNow,
                NOT_AFTER), req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(entryKeyReply(req, entry, certNotAfter,
                rootUntilNow, NOT_AFTER), req, serverKey, "pay", NOW + 1), "root past, entry-key form");
        JsonValue.Obj ringUntilNow = entryKeyReply(req, entry, certNotAfter, serverRoot, NOW);
        assertEquals(ReplyCheck.ATTESTED, check(ringUntilNow, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(ringUntilNow, req, serverKey, "pay", NOW + 1),
                "keyring past");

        SignedRoot expired = SignedRoot.sign(rootBytes, "v1", NOW - 1, serverPolicy.getPrivate());
        SignedRoot extended = new SignedRoot(expired.rootId(), expired.root(), expired.sig(), NOT_AFTER);
        assertTrue(extended.isCurrent(NOW));
        assertFalse(extended.verify(serverPolicy.getPublic()));
        JsonValue.Obj byEntry = entryKeyReply(req, entry, certNotAfter, extended, NOT_AFTER);
        assertEquals(new JsonValue.Int(NOT_AFTER), member(byEntry, "serverRoot").get("notAfter"));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(byEntry, req, serverKey, "pay", NOW));

        String pn = Sessions.newNonce();
        String ps = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), pn, clientKey,
                clientRing);
        Map<String, String> ring = Map.of("pay", "server-key");
        JsonValue.Obj withoutWindow = wire(Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, null,
                null, null, pn, ps, "attested", List.of(), null), serverPolicy.getPrivate()));
        assertEquals(ReplyCheck.ATTESTED, check(withoutWindow, req, serverKey, "pay", NOW));
        JsonValue.Obj withWindow = wire(Sessions.signReply(new SessionReply(serverRoot, serverKey, ring, null,
                NOT_AFTER, null, pn, ps, "attested", List.of(), null), serverPolicy.getPrivate()));
        assertNotNull(withWindow.get("serverKeyringNotAfter"));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(withWindow, req, serverKey, "pay", NOW));

        JsonValue.Obj rootWindowDropped = with(policyForm, "serverRoot",
                without(member(policyForm, "serverRoot"), "notAfter"));
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(rootWindowDropped, req, serverKey, "pay", NOW));
        JsonValue.Obj ringWindowDropped =
                without(entryKeyReply(req, entry, certNotAfter, serverRoot, NOT_AFTER), "serverKeyringNotAfter");
        assertEquals(ReplyCheck.MALFORMED_REPLY, check(ringWindowDropped, req, serverKey, "pay", NOW));
    }

    /** An entry-key reply: server root and keyring, the keyring's window beside it as on the request. */
    private JsonValue.Obj entryKeyReply(SessionRequest req, KeyPair entry, long certNotAfter) {
        return entryKeyReply(req, entry, certNotAfter, serverRoot, NOT_AFTER);
    }

    /** An entry-key reply carrying {@code root} and a keyring signed until {@code ringNotAfter}. */
    private JsonValue.Obj entryKeyReply(SessionRequest req, KeyPair entry, long certNotAfter, SignedRoot root,
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
     * moved by a millisecond fails the signature; one dropped, one of another type, or a number that is not a
     * protocol integer ({@code 1.8302976e12} for the same integer included) is malformed.
     */
    @Test
    void replyNotAftersAreCarriedAndChecked() {
        SessionRequest req = request(clientRoot);
        JsonValue.Obj reply = entryKeyReply(req, Crypto.generateEd25519KeyPair(), NOW + 1000);
        assertEquals(new JsonValue.Int(NOT_AFTER), reply.get("serverKeyringNotAfter"));
        assertEquals(new JsonValue.Int(NOT_AFTER), member(reply, "serverRoot").get("notAfter"));
        assertEquals(ReplyCheck.ATTESTED, check(reply, req, serverKey, "pay", NOW));

        JsonValue.Obj ringMoved = with(reply, "serverKeyringNotAfter", new JsonValue.Int(NOT_AFTER + 1));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(ringMoved, req, serverKey, "pay", NOW));
        assertEquals(ReplyCheck.MALFORMED_REPLY,
                check(without(reply, "serverKeyringNotAfter"), req, serverKey, "pay", NOW));
        JsonValue.Obj rootMoved = with(reply, "serverRoot",
                with(member(reply, "serverRoot"), "notAfter", new JsonValue.Int(NOT_AFTER + 1)));
        assertEquals(ReplyCheck.BAD_SIGNATURE, check(rootMoved, req, serverKey, "pay", NOW));

        for (JsonValue bad : NOT_INTEGERS) {
            assertEquals(ReplyCheck.MALFORMED_REPLY,
                    check(with(reply, "serverKeyringNotAfter", bad), req, serverKey, "pay", NOW), bad.toString());
            assertEquals(ReplyCheck.MALFORMED_REPLY, check(with(reply, "serverRoot",
                    with(member(reply, "serverRoot"), "notAfter", bad)), req, serverKey, "pay", NOW), bad.toString());
        }
        String text = JsonWriter.text(reply);
        assertEquals(2, text.split("otAfter\":" + NOT_AFTER, -1).length - 1);
        for (String bad : NOT_PROTOCOL_INTEGERS) {
            assertEquals(ReplyCheck.MALFORMED_REPLY, Sessions.checkReply(
                    text.replace("otAfter\":" + NOT_AFTER, "otAfter\":" + bad), req, serverKey, "pay", NOW), bad);
        }
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
