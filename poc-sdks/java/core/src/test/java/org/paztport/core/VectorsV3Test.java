// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
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
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;

/**
 * Replays the committed v3 vectors in {@code spec/vectors/v3.json}, the file the TypeScript SDK also reads. One
 * test method per section, so a failure names the section. The {@code recordedLocalStep} section is not replayed:
 * local steps belong to the MCP profile, which this SDK, speaking v3 over HTTP only, does not implement; nor are
 * {@code responseAttestation}, {@code sessionParams}, {@code sessionResult}, {@code bindMcpCall} and
 * {@code bindResult}, which only that profile uses.
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

    private static Stamp stamp(JsonNode s) {
        return new Stamp(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
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
            assertEquals(l.get("hash").asText(), Base64Url.encode(
                    MerkleHash.leaf(Base64Url.decode(l.get("salt").asText()), l.get("path").asText())));
        }
        for (JsonNode n : m.get("nodes")) {
            assertEquals(n.get("hash").asText(), Base64Url.encode(
                    MerkleHash.node(
                            Base64Url.decode(n.get("left").asText()), Base64Url.decode(n.get("right").asText()))));
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
    void signingBytes() {
        for (JsonNode c : vectors.get("signingBytes")) {
            assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp(c.get("stamp")).signingBytes()));
        }
    }

    @Test
    void signatures() {
        for (JsonNode c : vectors.get("signatures")) {
            JsonNode f = c.get("fields");
            Stamp s = Stamp.sign(f.get("svc").asText(), f.get("inst").asText(), f.get("rid").asText(),
                    f.get("ts").asLong(), f.get("sess").asText(), f.get("rcv").asText(), f.get("bind").asText(),
                    f.get("infl").asText(), f.get("prev").asText(), priv(c.get("key").asText()));
            assertEquals(c.get("sig").asText(), s.sig());
        }
    }

    @Test
    void keyring() {
        for (JsonNode c : vectors.get("keyring")) {
            String name = c.get("name").asText();
            String pin = vectors.get("keys").get(c.get("policyKey").asText()).get("pub").asText();
            KeyringFile file;
            try {
                file = KeyringFile.parse(c.get("file").textValue());
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
                root = SignedRoot.parse(c.get("file").textValue());
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
     * A keyring, root or certificate whose file the reader refused, a {@code notAfter} that is missing or not a
     * protocol integer among the reasons: nothing signs it, it never verifies and it is current at no time, its
     * signature never consulted.
     */
    private static void refused(JsonNode c) {
        String name = c.get("name").asText();
        assertTrue(c.get("signingBytes").isNull(), name);
        assertFalse(c.get("verifies").asBoolean(), name);
        current(c, at -> false);
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
            ReplyCert cert;
            try {
                cert = ReplyCert.parse(c.get("file").textValue());
            } catch (IllegalArgumentException e) {
                refused(c);
                continue;
            }
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
            SessionRequest req = SessionRequest.parse(Vectors.tokenText(c.get("requestToken")));
            String reply = Vectors.tokenText(c.get("replyToken"));
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
        return RecordedSession.of(Vectors.tokenText(h.get("requestToken")), Vectors.tokenText(h.get("replyToken")),
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
            JsonNode limit = want.get("responseNotAfter");
            assertEquals(limit.isNull() ? OptionalLong.empty() : OptionalLong.of(limit.asLong()), s.responseNotAfter(),
                    name + ": responseNotAfter");
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
                SessionRequest request =
                        SessionRequest.parse(Vectors.tokenText(c.get("handshakes").get(index).get("requestToken")));
                SignedRoot clientRoot = request.clientRoot();
                Map<String, PublicKey> ring = new LinkedHashMap<>();
                request.clientKeyring().forEach((svc, key) -> ring.put(svc,
                        Crypto.decodePublicKey(Base64Url.decode(key))));
                // The session's windows are judged by callInSession, so the members have none.
                OfflineConfig cfg = new OfflineConfig(List.of(new PinnedKeyring(Keyring.of(ring), Long.MAX_VALUE)),
                        List.of(new PinnedRoot(Base64Url.decode(clientRoot.root()), clientRoot.rootId(),
                                Long.MAX_VALUE)), origins, sessions.get(index).sess(), records.spent(), null,
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
            KeyringFile serverKeyring = KeyringFile.parse(c.get("serverKeyringFile").textValue());
            // the server's own keyring is the one it signed
            assertTrue(serverKeyring.verifies(serverKey), name);
            assertEquals(c.get("expected").asText(), Sessions.status(
                    SessionRequest.parse(Vectors.tokenText(c.get("requestToken"))),
                    SignedRoot.parse(c.get("serverRootFile").textValue()), serverKeyring,
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
                SessionRequest.parse(Vectors.tokenText(c.get("requestToken")));
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

    /** A member's {@code notAfter}, or {@code absent} where it gives none. */
    private static long window(JsonNode member, long absent) {
        return member.has("notAfter") ? member.get("notAfter").asLong() : absent;
    }

    /**
     * A case's pinned keyrings: its {@code keyrings}, in place of {@code keyring}, each member's window its own or
     * {@code absent}; otherwise its one {@code keyring}, with the window {@code single}.
     */
    static List<PinnedKeyring> keyrings(JsonNode c, long single, long absent) {
        if (!c.has("keyrings")) {
            return List.of(new PinnedKeyring(keyring(c.get("keyring")), single));
        }
        assertFalse(c.has("keyring"), c.get("name").asText() + ": keyrings replace keyring");
        List<PinnedKeyring> out = new ArrayList<>();
        c.get("keyrings").forEach(k -> out.add(new PinnedKeyring(keyring(k.get("keyring")), window(k, absent))));
        return out;
    }

    /**
     * A case's pinned roots: its {@code roots}, each a policy's root and its window, its own or {@code absent};
     * otherwise {@code policy}'s root, with the window {@code single}. With {@code roots}, {@code policy} names only
     * where the case's proof comes from.
     */
    static List<PinnedRoot> roots(JsonNode c, long single, long absent) {
        if (!c.has("roots")) {
            return List.of(pinnedRoot(c.get("policy").asText(), single));
        }
        List<PinnedRoot> out = new ArrayList<>();
        c.get("roots").forEach(r -> out.add(pinnedRoot(r.get("policy").asText(), window(r, absent))));
        return out;
    }

    private static PinnedRoot pinnedRoot(String policy, long notAfter) {
        JsonNode p = vectors.get("policies").get(policy);
        return new PinnedRoot(Base64Url.decode(p.get("root").asText()), p.get("rootId").asText(), notAfter);
    }

    @Test
    void verify() {
        for (JsonNode c : vectors.get("verify")) {
            assertEquals(expectedLive(c), replayLive(c), c.get("name").asText());
        }
    }

    /** A live case run {@code uses} times against one nonce cache; the last result. */
    private static VerifyResult replayLive(JsonNode c) {
        JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        long now = c.get("now").asLong();
        long policyNotAfter = c.get("policyNotAfter").asLong();
        // A live member always has a window: one without is never current.
        VerifierConfig cfg = new VerifierConfig(keyrings(c, policyNotAfter, Long.MIN_VALUE),
                roots(c, policyNotAfter, Long.MIN_VALUE), policyNotAfter, origins,
                c.get("sess").asText(), new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong());
        JsonNode route = c.get("proofRoute");
        JsonNode peer = c.get("peer");
        VerifyInput in = new VerifyInput(Vectors.tokenText(c.get("chainToken")),
                c.get("expectedBind").asText(), Vectors.tokenText(c.get("influenceToken")), proof(policy, route),
                c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                peer.isNull() ? null : new Peer(peer.get("svc").asText(), peer.get("inst").asText()));
        Verifier verifier = new Verifier(cfg);
        VerifyResult result = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            result = verifier.verify(in);
        }
        return result;
    }

    private static VerifyResult expectedLive(JsonNode c) {
        JsonNode want = c.get("expected");
        return new VerifyResult(ReasonCode.valueOf(want.get("reason").asText()), want.get("suspectSvc").asText(),
                want.get("suspectInst").asText());
    }

    /**
     * The offline inputs a case gives; {@code run} absent means the run's recorded times are not compared, and a
     * {@code null} {@code recordedTs} is a record with no time.
     */
    static OfflineInput offlineInput(JsonNode c, JsonNode policy) {
        JsonNode t = c.get("recordedTs");
        Set<Long> run = null;
        if (!t.isNull() && t.has("run")) {
            run = new LinkedHashSet<>();
            for (JsonNode r : t.get("run")) {
                run.add(r.asLong());
            }
        }
        return new OfflineInput(Vectors.tokenText(c.get("chainToken")), c.get("expectedBind").asText(),
                Vectors.tokenText(c.get("influenceToken")), proof(policy, c.get("proofRoute")),
                c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                c.get("rid").asText(),
                t.isNull() ? null : new RecordedTimes(t.get("last").asLong(), run), c.get("prompt").asText());
    }

    /** The offline config a case gives: offline, a member without a window counts for every record. */
    static OfflineConfig offlineConfig(JsonNode c) {
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        Set<String> seen = new LinkedHashSet<>();
        c.get("seen").forEach(k -> seen.add(k.asText()));
        return new OfflineConfig(keyrings(c, Long.MAX_VALUE, Long.MAX_VALUE), roots(c, Long.MAX_VALUE, Long.MAX_VALUE),
                origins, c.get("sess").asText(), seen, null, limit(c.get("runMaxAgeMs")), limit(c.get("callMaxAgeMs")));
    }

    /** An age limit a case gives; {@code null} is a limit not configured. */
    private static Long limit(JsonNode n) {
        return n.isNull() ? null : n.asLong();
    }

    @Test
    void offline() {
        for (JsonNode c : vectors.get("offline")) {
            assertEquals(expectedOffline(c), replayOffline(c), c.get("name").asText());
        }
    }

    private static OfflineResult replayOffline(JsonNode c) {
        return OfflineVerifier.verify(offlineInput(c, policy(c)), offlineConfig(c));
    }

    private static OfflineResult expectedOffline(JsonNode c) {
        JsonNode want = c.get("expected");
        return new OfflineResult(ReasonCode.valueOf(want.get("reason").asText()), want.get("suspectSvc").asText(),
                want.get("suspectInst").asText());
    }

    /**
     * Every verify and offline case written in the single form, rewritten as the optional {@code keyrings} and
     * {@code roots}, gives its recorded answer: the replay reads the arrays a case may carry, beside the committed
     * cases that carry them. Each case is rewritten twice: one keyring, and its services split one to a keyring, so
     * a stamp's key comes from whichever keyring holds it. Live, each member's window is the case's
     * {@code policyNotAfter}; offline, a member has none.
     */
    @Test
    void theOptionalArraysGiveTheAnswersOfTheirSingletons() {
        for (JsonNode c : vectors.get("verify")) {
            if (c.has("keyrings") || c.has("roots")) {
                continue; // already written as arrays: verify() replays it
            }
            for (boolean split : new boolean[] {false, true}) {
                assertEquals(expectedLive(c), replayLive(asArrays(c, c.get("policyNotAfter"), split)),
                        c.get("name").asText() + (split ? ", split" : ""));
            }
        }
        for (JsonNode c : vectors.get("offline")) {
            if (c.has("keyrings") || c.has("roots")) {
                continue; // already written as arrays: offline() replays it
            }
            for (boolean split : new boolean[] {false, true}) {
                assertEquals(expectedOffline(c), replayOffline(asArrays(c, null, split)),
                        c.get("name").asText() + (split ? ", split" : ""));
            }
        }
        // And what the arrays pin is what is used: the keyrings in place of keyring, the roots in place of policy's
        // root, which still gives the proof, and each member's own window.
        JsonNode ok = caseNamed("verify", "mcp call ok");
        ObjectNode piless = (ObjectNode) asArrays(ok, ok.get("policyNotAfter"), true);
        ((ArrayNode) piless.get("keyrings")).remove(1);
        assertEquals(ReasonCode.BAD_SIGNATURE, replayLive(piless).reason());
        ObjectNode elsewhere = (ObjectNode) asArrays(ok, ok.get("policyNotAfter"), false);
        ((ObjectNode) elsewhere.get("roots").get(0)).put("policy", "server");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, replayLive(elsewhere).reason());
        JsonNode recorded = offlineCase("recorded call");
        long before = recorded.get("recordedTs").get("last").asLong() - 1;
        ObjectNode lapsed = (ObjectNode) asArrays(recorded, MAPPER.getNodeFactory().numberNode(before), false);
        assertEquals(ReasonCode.POLICY_EXPIRED, replayOffline(lapsed).reason());
    }


    /**
     * {@code c} with its {@code keyring} as {@code keyrings}, whole or split one service to a keyring, and its
     * {@code policy}'s root as {@code roots}, each member until {@code notAfter}, or with no window when it is null.
     */
    private static JsonNode asArrays(JsonNode c, JsonNode notAfter, boolean split) {
        ObjectNode o = c.deepCopy();
        JsonNode keyring = o.remove("keyring");
        ArrayNode keyrings = o.putArray("keyrings");
        List<JsonNode> parts = new ArrayList<>();
        if (split) {
            keyring.properties().forEach(e -> parts.add(MAPPER.createObjectNode().set(e.getKey(), e.getValue())));
        } else {
            parts.add(keyring);
        }
        for (JsonNode part : parts) {
            ObjectNode member = keyrings.addObject();
            member.set("keyring", part);
            if (notAfter != null) {
                member.set("notAfter", notAfter);
            }
        }
        ObjectNode root = o.putArray("roots").addObject().put("policy", c.get("policy").asText());
        if (notAfter != null) {
            root.set("notAfter", notAfter);
        }
        return o;
    }

    static JsonNode offlineCase(String name) {
        return caseNamed("offline", name);
    }

    private static JsonNode caseNamed(String section, String name) {
        for (JsonNode c : vectors.get(section)) {
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
