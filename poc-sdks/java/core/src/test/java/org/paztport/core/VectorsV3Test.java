// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongPredicate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.influence.InfluenceFact;
import org.paztport.core.influence.InfluenceRule;
import org.paztport.core.offline.OfflineConfig;
import org.paztport.core.offline.OfflineInput;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.offline.OfflineVerifier;
import org.paztport.core.offline.RecordSet;
import org.paztport.core.offline.RecordedSession;
import org.paztport.core.offline.RecordedTimes;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleHash;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.core.verify.VerifyResult;

/**
 * Replays the committed v3 vectors in {@code spec/vectors/v3.json}, the file the TypeScript SDK also reads. One
 * test method per section, so a failure names the section. The {@code recordedLocalStep} section is not replayed:
 * local steps belong to the MCP profile, which this SDK, speaking v3 over HTTP only, does not implement; nor are
 * {@code responseAttestation}, {@code bindMcpCall} and {@code bindResult}, which only that profile uses.
 */
class VectorsV3Test {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static JsonNode vectors;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v3.json");
    }

    @Test
    void influence() throws IOException {
        for (JsonNode c : vectors.get("influence")) {
            String name = c.get("name").asText();
            List<InfluenceEntry> normalised = Influence.normalise(Influence.parse(Vectors.text(c.get("entries"))));
            assertEquals(c.get("normalized"), MAPPER.readTree(Influence.toJson(normalised)), name);
            assertEquals(c.get("commitment").asText(),
                    Influence.commit(Influence.parse(Vectors.text(c.get("entries")))), name);
        }
    }

    @Test
    void rule() {
        for (JsonNode c : vectors.get("rule")) {
            List<InfluenceFact> facts = new ArrayList<>();
            for (JsonNode f : c.get("influence")) {
                facts.add(new InfluenceFact(
                        InfluenceClass.fromWire(f.get("cls").asText()),
                        f.has("owner") ? f.get("owner").asText() : null));
            }
            JsonNode dest = c.get("destinationOwner");
            String owner = dest == null || dest.isNull() ? null : dest.asText();
            assertEquals(c.get("refused").asBoolean(), InfluenceRule.publicWriteRefused(facts, owner),
                    c.get("name").asText());
        }
    }

    private static StampV3 stamp(JsonNode s) {
        return new StampV3(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
                s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(), s.get("infl").asText(),
                s.get("prev").asText(), "");
    }

    private static PrivateKey priv(String name) {
        return Crypto.decodePrivateKey(Base64Url.decode(vectors.get("keys").get(name).get("priv").asText()));
    }

    @Test
    void commitInfluence() {
        JsonNode c = vectors.get("commitInfluence");
        assertEquals(c.get("expected").asText(), Influence.commit(Influence.parse(Vectors.text(c.get("entries")))));
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
                c.get("callId").asText(), ContentLabel.parseAll(Vectors.text(c.get("labels")))));
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

    @Test
    void merkle() {
        JsonNode m = vectors.get("merkle");
        for (JsonNode l : m.get("leaves")) {
            assertEquals(l.get("hash").asText(),
                    Base64Url.encode(MerkleHash.leaf(Base64Url.decode(l.get("salt").asText()), l.get("path").asText())));
        }
        for (JsonNode n : m.get("nodes")) {
            assertEquals(n.get("hash").asText(), Base64Url.encode(
                    MerkleHash.node(Base64Url.decode(n.get("left").asText()), Base64Url.decode(n.get("right").asText()))));
        }
        byte[] root = Base64Url.decode(m.get("root").asText());
        int proofs = 0;
        for (var e : m.get("proofs").properties()) {
            String path = e.getKey();
            MerkleProof proof = MerkleProof.parse(Vectors.text(e.getValue()));
            assertTrue(proof.verify(path, root), path);
            String header = m.get("proofHeaders").get(path).asText();
            assertEquals(proof, MerkleProof.decode(header), path);
            assertEquals(header, proof.encode(), path);
            proofs++;
        }
        assertEquals(m.get("proofHeaders").size(), proofs);
    }

    @Test
    void signingBytesV3() {
        for (JsonNode c : vectors.get("signingBytesV3")) {
            assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp(c.get("stamp")).signingBytes()));
        }
    }

    @Test
    void signatures() {
        for (JsonNode c : vectors.get("signatures")) {
            JsonNode f = c.get("fields");
            StampV3 s = StampV3.sign(f.get("svc").asText(), f.get("inst").asText(), f.get("rid").asText(),
                    f.get("ts").asLong(), f.get("sess").asText(), f.get("rcv").asText(), f.get("bind").asText(),
                    f.get("infl").asText(), f.get("prev").asText(), priv(c.get("key").asText()));
            assertEquals(c.get("sig").asText(), s.sig());
        }
    }

    @Test
    void keyring() {
        for (JsonNode c : vectors.get("keyring")) {
            String name = c.get("name").asText();
            JsonNode signed = c.get("signed");
            String pin = vectors.get("keys").get(c.get("policyKey").asText()).get("pub").asText();
            KeyringFile file;
            try {
                file = KeyringFile.parse(Vectors.json(signed));
            } catch (IllegalArgumentException e) {
                refused(c);
                continue;
            }
            assertEquals(c.get("signingBytes").asText(), Base64Url.encode(
                    KeyringFile.signingBytes(file.policy(), file.services(), file.notAfter())), name);
            assertEquals(c.get("verifies").asBoolean(), file.verifies(pin), name);
            current(c, file::isCurrent);
            // Every keyring that verifies is reproduced byte for byte by signing it.
            if (c.get("verifies").asBoolean()) {
                assertEquals(c.get("sig").asText(), KeyringFile.sign(file.services(), file.policy(), file.notAfter(),
                        priv(c.get("policyKey").asText())).sig(), name);
            }
        }
    }

    @Test
    void root() {
        JsonNode cases = vectors.get("root");
        assertTrue(cases != null && cases.size() > 0, "root section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(
                    vectors.get("keys").get(c.get("policyKey").asText()).get("pub").asText()));
            SignedRoot root;
            try {
                root = SignedRoot.parse(Vectors.json(c.get("signed")));
            } catch (IllegalArgumentException e) {
                refused(c);
                continue;
            }
            JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
            assertEquals(policy.get("root").asText(), root.root(), name);
            assertEquals(policy.get("rootId").asText(), root.rootId(), name);
            assertEquals(c.get("signingBytes").asText(), Base64Url.encode(
                    SignedRoot.signingBytes(root.rootId(), root.root(), root.notAfter())), name);
            assertEquals(c.get("verifies").asBoolean(), root.verify(pin), name);
            current(c, root::isCurrent);
            if (c.get("verifies").asBoolean()) {
                assertEquals(root.sig(), SignedRoot.sign(root.rootBytes(), root.rootId(), root.notAfter(),
                        priv(c.get("policyKey").asText())).sig(), name);
            }
        }
    }

    /**
     * A keyring or root the reader refused: its {@code notAfter} is missing or not an integer in range, so nothing
     * signs it, it never verifies and it is current at no time, its signature never consulted.
     */
    private static void refused(JsonNode c) {
        String name = c.get("name").asText();
        assertTrue(c.get("signingBytes").isNull(), name);
        assertFalse(c.get("verifies").asBoolean(), name);
        current(c, at -> false);
    }

    /** The case named {@code name} in {@code section}. */
    static JsonNode named(String section, String name) {
        for (JsonNode c : vectors.get(section)) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException(section + " has no case " + name);
    }

    /**
     * The cases that tie the two readers' reading of a {@code notAfter} together: 2^53 is refused, and a value the
     * file writes with a fraction reaches the strict reader as a floating-point number, which it reads by value as
     * the integer the signature is over.
     */
    @Test
    void notAfterJudgedByValue() {
        String pinText = vectors.get("keys").get("client-policy").get("pub").asText();
        PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(pinText));
        JsonNode ringTooLarge = named("keyring", "notAfter 2^53");
        assertEquals("9007199254740992", ringTooLarge.get("signed").get("notAfter").asText());
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(Vectors.json(ringTooLarge.get("signed"))));
        JsonNode rootTooLarge = named("root", "notAfter 2^53");
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(Vectors.json(rootTooLarge.get("signed"))));

        JsonNode ringWritten = named("keyring", "notAfter written 1798761600000.0").get("signed");
        assertTrue(ringWritten.get("notAfter").isFloatingPointNumber(), "the file writes it with a fraction");
        KeyringFile ring = KeyringFile.parse(Vectors.json(ringWritten));
        assertEquals(1_798_761_600_000L, ring.notAfter());
        assertTrue(ring.verifies(pinText));
        assertEquals(named("keyring", "signed").get("sig").asText(), ring.sig());

        JsonNode rootWritten = named("root", "notAfter written 1798761600000.0").get("signed");
        assertTrue(rootWritten.get("notAfter").isFloatingPointNumber(), "the file writes it with a fraction");
        SignedRoot root = SignedRoot.parse(Vectors.json(rootWritten));
        assertEquals(1_798_761_600_000L, root.notAfter());
        assertTrue(root.verify(pin));
    }

    /** Checks a case's {@code current} answers, if it has any, against {@code isCurrent}. */
    private static void current(JsonNode c, LongPredicate isCurrent) {
        JsonNode answers = c.get("current");
        if (answers == null) {
            return;
        }
        for (JsonNode a : answers) {
            assertEquals(a.get("current").asBoolean(), isCurrent.test(a.get("at").asLong()),
                    c.get("name").asText() + " at " + a.get("at").asText());
        }
    }

    @Test
    void replyCert() {
        JsonNode cases = vectors.get("replyCert");
        assertTrue(cases != null && cases.size() > 0, "replyCert section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            ReplyCert cert = ReplyCert.parse(Vectors.json(c.get("cert")));
            assertEquals(c.get("signingBytes").asText(), Base64Url.encode(
                    ReplyCert.signingBytes(cert.policy(), cert.svc(), cert.key(), cert.notAfter())), name);
            String pin = vectors.get("keys").get(c.get("pin").asText()).get("pub").asText();
            assertEquals(c.get("verifies").asBoolean(), cert.verifies(pin), name);
            // Every certificate that verifies is reproduced byte for byte by issuing it.
            if (c.get("verifies").asBoolean()) {
                assertEquals(cert.sig(), ReplyCert.issue(cert.policy(), cert.svc(), cert.key(), cert.notAfter(),
                        priv(c.get("signer").asText())).sig(), name);
            }
        }
    }

    @Test
    void sessionReply() {
        JsonNode cases = vectors.get("sessionReply");
        assertTrue(cases != null && cases.size() > 0, "sessionReply section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            String pin = vectors.get("keys").get(c.get("pin").asText()).get("pub").asText();
            SessionRequest req = SessionRequest.parse(Vectors.json(c.get("request")));
            String reply = Vectors.json(c.get("reply"));
            String entry = c.get("serverEntry").asText();
            long now = c.get("now").asLong();
            assertEquals(ReplyCheck.valueOf(c.get("expected").asText()), Sessions.checkReply(reply, req, pin, entry,
                    now), name);
            // Offline, judged at the same time, the handshake is attested exactly when the live check says so.
            assertEquals(c.get("expected").asText().equals("ATTESTED"),
                    Sessions.attestedOffline(reply, req, pin, entry, now), name + " offline");
        }
    }

    /** A recorded handshake case's session: from its request, reply, pin and the verifier's configured entry. */
    private static RecordedSession recordedSession(JsonNode h) {
        return RecordedSession.of(Vectors.json(h.get("request")), Vectors.json(h.get("reply")),
                vectors.get("keys").get(h.get("pin").asText()).get("pub").asText(), h.get("serverEntry").asText());
    }

    @Test
    void recordedHandshake() {
        JsonNode cases = vectors.get("recordedHandshake");
        assertTrue(cases != null && cases.size() > 0, "recordedHandshake section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            RecordedSession s = recordedSession(c);
            JsonNode want = c.get("expected");
            assertEquals(want.get("attested").asBoolean(), s.attested(), name + ": attested");
            for (int i = 0; i < c.get("at").size(); i++) {
                long at = c.get("at").get(i).asLong();
                assertEquals(want.get("attestedAt").get(i).asBoolean(), s.attestedAt(at), name + ": at " + at);
            }
            assertEquals(want.get("responseNotAfter").asLong(), s.responseNotAfter(), name + ": responseNotAfter");
        }
    }

    /**
     * Each case is one record set: its calls in order against one set of spent nonce keys, each by the offline
     * verifier in the session of the handshake it names (that request's client keyring and root, that reply's
     * session id), then limited to that session.
     */
    @Test
    void recordedCall() {
        JsonNode cases = vectors.get("recordedCall");
        assertTrue(cases != null && cases.size() > 0, "recordedCall section");
        boolean outsideSession = false;
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            List<RecordedSession> sessions = new ArrayList<>();
            c.get("handshakes").forEach(h -> sessions.add(recordedSession(h)));
            RecordSet records = new RecordSet();
            Set<String> origins = new LinkedHashSet<>();
            c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
            assertEquals(c.get("calls").size(), c.get("expected").size(), name);
            for (int i = 0; i < c.get("calls").size(); i++) {
                JsonNode call = c.get("calls").get(i);
                int index = call.get("handshake").asInt();
                JsonNode request = c.get("handshakes").get(index).get("request");
                JsonNode clientRoot = request.get("clientRoot");
                Map<String, PublicKey> ring = new LinkedHashMap<>();
                request.get("clientKeyring").properties().forEach(e -> ring.put(e.getKey(),
                        Crypto.decodePublicKey(Base64Url.decode(e.getValue().asText()))));
                OfflineConfig cfg = new OfflineConfig(Keyring.of(ring),
                        Base64Url.decode(clientRoot.get("root").asText()), clientRoot.get("rootId").asText(), origins,
                        sessions.get(index).sess(), records.spent(), null,
                        c.get("runMaxAgeMs").asLong(), c.get("callMaxAgeMs").asLong());
                OfflineResult result = OfflineVerifier.verify(offlineInput(call, policy(call)), cfg);
                ReasonCode reason = RecordSet.callInSession(sessions.get(index), result.reason(),
                        call.get("recordedTs").get("last").asLong());
                JsonNode want = c.get("expected").get(i);
                assertEquals(ReasonCode.valueOf(want.get("reason").asText()), reason, name + " call " + i);
                outsideSession |= reason == ReasonCode.OUTSIDE_SESSION;
            }
        }
        assertTrue(outsideSession, "a case gives OUTSIDE_SESSION");
    }

    @Test
    void sessionStatus() {
        JsonNode cases = vectors.get("sessionStatus");
        assertTrue(cases != null && cases.size() > 0, "sessionStatus section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            Set<String> pinned = new LinkedHashSet<>();
            c.get("pinned").forEach(n -> pinned.add(vectors.get("keys").get(n.asText()).get("pub").asText()));
            String serverKey = vectors.get("keys").get(c.get("serverPolicyKey").asText()).get("pub").asText();
            KeyringFile serverKeyring = KeyringFile.parse(Vectors.json(c.get("serverKeyring")));
            // the server's own keyring is the one it signed
            assertTrue(serverKeyring.verifies(serverKey), name);
            assertEquals(c.get("expected").asText(), Sessions.status(
                    SessionRequest.parse(Vectors.json(c.get("request"))),
                    SignedRoot.parse(Vectors.json(c.get("serverRoot"))), serverKeyring,
                    Crypto.decodePublicKey(Base64Url.decode(serverKey)), pinned, c.get("now").asLong()), name);
        }
    }

    @Test
    void sessionRequest() {
        JsonNode cases = vectors.get("sessionRequest");
        assertTrue(cases != null && cases.size() > 0, "sessionRequest section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            String got = "OK";
            try {
                SessionRequest.parse(Vectors.json(c.get("request")));
            } catch (IllegalArgumentException e) {
                got = "MALFORMED";
            }
            assertEquals(c.get("expected").asText(), got, name);
        }
    }

    /** The policy's proof for {@code route}, from its token, or null for no proof. */
    static String proof(JsonNode policy, JsonNode route) {
        return route.isNull() ? null : Vectors.tokenText(policy.get("proofTokens").get(route.asText()));
    }

    static Keyring keyring(JsonNode names) {
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        names.properties().forEach(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(vectors.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        return Keyring.of(keys);
    }

    @Test
    void verify() {
        for (JsonNode c : vectors.get("verify")) {
            String name = c.get("name").asText();
            JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
            Set<String> origins = new LinkedHashSet<>();
            c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
            long now = c.get("now").asLong();
            VerifierConfigV3 cfg = new VerifierConfigV3(keyring(c.get("keyring")),
                    Base64Url.decode(policy.get("root").asText()), policy.get("rootId").asText(),
                    c.get("policyNotAfter").asLong(), origins,
                    c.get("sess").asText(), new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                    c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong());
            JsonNode route = c.get("proofRoute");
            JsonNode peer = c.get("peer");
            VerifyInputV3 in = new VerifyInputV3(Vectors.tokenText(c.get("chainToken")),
                    c.get("expectedBind").asText(), Vectors.tokenText(c.get("influenceToken")), proof(policy, route),
                    c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                    peer.isNull() ? null : new Peer(peer.get("svc").asText(), peer.get("inst").asText()));
            VerifierV3 verifier = new VerifierV3(cfg);
            VerifyResult result = null;
            for (int i = 0; i < c.get("uses").asInt(); i++) {
                result = verifier.verify(in);
            }
            JsonNode want = c.get("expected");
            assertEquals(new VerifyResult(ReasonCode.valueOf(want.get("reason").asText()),
                    want.get("suspectSvc").asText(), want.get("suspectInst").asText()), result, name);
        }
    }

    /** The offline inputs a case gives; {@code run} absent means the run's recorded times are not compared. */
    static OfflineInput offlineInput(JsonNode c, JsonNode policy) {
        JsonNode t = c.get("recordedTs");
        Set<Long> run = null;
        if (t.has("run")) {
            run = new LinkedHashSet<>();
            for (JsonNode r : t.get("run")) {
                run.add(r.asLong());
            }
        }
        return new OfflineInput(Vectors.tokenText(c.get("chainToken")), c.get("expectedBind").asText(),
                Vectors.tokenText(c.get("influenceToken")), proof(policy, c.get("proofRoute")),
                c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                c.get("rid").asText(),
                new RecordedTimes(t.get("last").asLong(), run), c.get("prompt").asText());
    }

    static OfflineConfig offlineConfig(JsonNode c, JsonNode policy) {
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        Set<String> seen = new LinkedHashSet<>();
        c.get("seen").forEach(k -> seen.add(k.asText()));
        return new OfflineConfig(keyring(c.get("keyring")), Base64Url.decode(policy.get("root").asText()),
                policy.get("rootId").asText(), origins, c.get("sess").asText(), seen, null,
                c.get("runMaxAgeMs").asLong(), c.get("callMaxAgeMs").asLong());
    }

    @Test
    void offline() {
        for (JsonNode c : vectors.get("offline")) {
            JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
            OfflineResult result = OfflineVerifier.verify(offlineInput(c, policy), offlineConfig(c, policy));
            JsonNode want = c.get("expected");
            assertEquals(new OfflineResult(ReasonCode.valueOf(want.get("reason").asText()),
                    want.get("suspectSvc").asText(), want.get("suspectInst").asText()),
                    result, c.get("name").asText());
        }
    }

    static JsonNode offlineCase(String name) {
        for (JsonNode c : vectors.get("offline")) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException(name);
    }

    static JsonNode policy(JsonNode c) {
        return vectors.get("policies").get(c.get("policy").asText());
    }
}
