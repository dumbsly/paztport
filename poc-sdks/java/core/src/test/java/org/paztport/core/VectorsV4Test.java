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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.EnumSet;
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
import org.paztport.core.session.Requirement;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.HandOver.StampItems;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;

/**
 * Replays {@code spec/vectors/v4.json}, the file the TypeScript SDK also reads. One test method per section, so a
 * failure names the section. Not replayed (spec/README.md, Conformance): {@code recordedLocalStep},
 * {@code responseAttestation}, {@code sessionParams}, {@code sessionResult}, {@code bindMcpCall} and
 * {@code bindResult}, which belong to the MCP profile this SDK does not implement, and in the member
 * {@code influence}, {@code response} and the {@code request} cases whose {@code served} is not empty, which record
 * the MCP rule.
 */
class VectorsV4Test {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static JsonNode v4;

    @BeforeAll
    static void load() throws IOException {
        v4 = Vectors.load("v4.json");
    }

    private static PrivateKey priv(String name) {
        return Crypto.decodePrivateKey(Base64Url.decode(v4.get("keys").get(name).get("priv").asText()));
    }

    @Test
    void deriveSessionId() {
        JsonNode d = v4.get("deriveSessionId");
        assertTrue(d != null && d.get("cases").size() > 0, "deriveSessionId section");
        assertTrue(v4.get("fixedInputs").size() > 0, "fixedInputs section");
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
        JsonNode f = v4.get("fixedInputs").get(name);
        byte[] bytes = new byte[f.get("length").asInt()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (f.get("start").asInt() + i);
        }
        String encoded = Base64Url.encode(bytes);
        assertEquals(f.get("encoded").asText(), encoded);
        return encoded;
    }

    @Test
    void replyCert() {
        JsonNode cases = v4.get("replyCert");
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
            String pin = v4.get("keys").get(c.get("pin").asText()).get("pub").asText();
            assertEquals(c.get("verifies").asBoolean(), cert.verifies(pin), name);
            // Every certificate that verifies is reproduced byte for byte by issuing it.
            if (c.get("verifies").asBoolean()) {
                assertEquals(cert.sig(), ReplyCert.issue(cert.policy(), cert.svc(), cert.key(), cert.notAfter(),
                        priv(c.get("signer").asText())).sig(), name);
            }
        }
    }

    /**
     * The client's check, with the extensions the case requires, and the same reply read offline: it opened an
     * attested session exactly when the check gives ATTESTED or EXTENSION_REQUIRED, since step 5 is live only.
     */
    @Test
    void sessionReply() {
        JsonNode cases = v4.get("sessionReply");
        assertTrue(cases != null && cases.size() > 0, "sessionReply section");
        Set<ReplyCheck> given = EnumSet.noneOf(ReplyCheck.class);
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            String pin = v4.get("keys").get(c.get("pin").asText()).get("pub").asText();
            SessionRequest req = SessionRequest.parse(Vectors.tokenText(c.get("requestToken")));
            String reply = Vectors.tokenText(c.get("replyToken"));
            String entry = c.get("serverEntry").asText();
            long now = c.get("now").asLong();
            Set<String> requires = new LinkedHashSet<>();
            if (c.has("requires")) {
                c.get("requires").forEach(n -> requires.add(n.textValue()));
            }
            ReplyCheck want = ReplyCheck.valueOf(c.get("expected").asText());
            ReplyCheck got = Sessions.checkReply(reply, req, pin, entry, now, Requirement.of(requires, false));
            assertEquals(want, got, name);
            given.add(got);
            assertEquals(want == ReplyCheck.ATTESTED || want == ReplyCheck.EXTENSION_REQUIRED,
                    Sessions.attestedOffline(reply, req, pin, entry, now), name + " offline");
        }
        assertEquals(EnumSet.allOf(ReplyCheck.class), given, "the section gives each of the six outcomes");
    }

    /** What a client that requires extensions may do after the handshake (sessions.md). */
    @Test
    void sessionRequirement() {
        JsonNode cases = v4.get("sessionRequirement");
        assertTrue(cases != null && cases.size() > 0, "sessionRequirement section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            Set<String> requires = new LinkedHashSet<>();
            c.get("requires").forEach(n -> requires.add(n.textValue()));
            List<String> listed = new ArrayList<>();
            c.get("listed").forEach(n -> listed.add(n.textValue()));
            ReplyCheck check = c.get("check").isNull() ? null : ReplyCheck.valueOf(c.get("check").textValue());
            Requirement.Calls got = Requirement.of(requires, c.get("continueWithout").booleanValue())
                    .callsAfter(check, listed);
            List<String> carried = new ArrayList<>();
            c.get("expected").get("requires").forEach(n -> carried.add(n.textValue()));
            assertEquals(c.get("expected").get("calls").booleanValue(), got.calls(), name);
            assertEquals(carried, got.requires(), name);
        }
    }

    /** A recorded handshake case's session: from its request, reply, pin and the verifier's configured entry. */
    private static RecordedSession recordedSession(JsonNode h) {
        return RecordedSession.of(Vectors.tokenText(h.get("requestToken")), Vectors.tokenText(h.get("replyToken")),
                v4.get("keys").get(h.get("pin").asText()).get("pub").asText(), h.get("serverEntry").asText());
    }

    @Test
    void recordedHandshake() {
        JsonNode cases = v4.get("recordedHandshake");
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

    @Test
    void sessionStatus() {
        JsonNode cases = v4.get("sessionStatus");
        assertTrue(cases != null && cases.size() > 0, "sessionStatus section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            Set<String> pinned = new LinkedHashSet<>();
            c.get("pinned").forEach(n -> pinned.add(v4.get("keys").get(n.asText()).get("pub").asText()));
            String serverKey = v4.get("keys").get(c.get("serverPolicyKey").asText()).get("pub").asText();
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
        JsonNode cases = v4.get("sessionRequest");
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

    @Test
    void blocksRead() {
        int read = 0;
        int refused = 0;
        for (JsonNode c : v4.get("blocks").get("read")) {
            String token = Vectors.tokenText(c.get("token"));
            String name = c.get("name").textValue();
            if (c.get("expected").textValue().equals("OK")) {
                read++;
                List<Block> blocks = Block.parseAll(token);
                assertEquals(Vectors.text(c.get("blocks")), Block.toJson(blocks), name);
            } else {
                refused++;
                assertThrows(IllegalArgumentException.class, () -> Block.parseAll(token), name);
            }
        }
        assertTrue(read > 0 && refused > 0, "the section holds both outcomes");
    }

    @Test
    void blocksCommit() {
        int cases = 0;
        for (JsonNode c : v4.get("blocks").get("commit")) {
            cases++;
            String name = c.get("name").textValue();
            List<Block> one = Block.parseAll("[" + Vectors.text(c.get("block")) + "]");
            assertEquals(c.get("jcs").textValue(), one.get(0).toJson(), name);
            assertEquals(c.get("ext").textValue(), one.get(0).commit(), name);
        }
        assertTrue(cases > 0);
    }

    // --- The primitives: signed bytes, signatures, the signed material, the tree and the bindings ---

    private static Stamp stamp(JsonNode s) {
        return new Stamp(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(), s.get("ts").asLong(),
                s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(), s.get("ext").asText(),
                s.get("prev").asText(), "");
    }

    @Test
    void signingBytes() {
        JsonNode cases = v4.get("signingBytes");
        assertTrue(cases != null && cases.size() > 0, "signingBytes section");
        for (JsonNode c : cases) {
            assertEquals(c.get("hex").asText(), HexFormat.of().formatHex(stamp(c.get("stamp")).signingBytes()));
        }
    }

    @Test
    void signatures() {
        JsonNode cases = v4.get("signatures");
        assertTrue(cases != null && cases.size() > 0, "signatures section");
        for (JsonNode c : cases) {
            JsonNode f = c.get("fields");
            Stamp s = Stamp.sign(f.get("svc").asText(), f.get("inst").asText(), f.get("rid").asText(),
                    f.get("ts").asLong(), f.get("sess").asText(), f.get("rcv").asText(), f.get("bind").asText(),
                    f.get("ext").asText(), f.get("prev").asText(), priv(c.get("key").asText()));
            assertEquals(c.get("sig").asText(), s.sig());
        }
    }

    @Test
    void keyring() {
        JsonNode cases = v4.get("keyring");
        assertTrue(cases != null && cases.size() > 0, "keyring section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            String pin = v4.get("keys").get(c.get("policyKey").asText()).get("pub").asText();
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
        JsonNode cases = v4.get("root");
        assertTrue(cases != null && cases.size() > 0, "root section");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(
                    v4.get("keys").get(c.get("policyKey").asText()).get("pub").asText()));
            SignedRoot root;
            try {
                root = SignedRoot.parse(c.get("file").textValue());
            } catch (IllegalArgumentException e) {
                refused(c);
                continue;
            }
            JsonNode policy = v4.get("policies").get(c.get("policy").asText());
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
    static void refused(JsonNode c) {
        String name = c.get("name").asText();
        assertTrue(c.get("signingBytes").isNull(), name);
        assertFalse(c.get("verifies").asBoolean(), name);
        current(c, at -> false);
    }

    /** Checks a case's {@code current} answers, if it has any, against {@code isCurrent}. */
    static void current(JsonNode c, LongPredicate isCurrent) {
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
    void merkle() {
        JsonNode m = v4.get("merkle");
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
        assertTrue(proofs > 0, "merkle proofs");
        assertEquals(m.get("proofHeaders").size(), proofs);
    }

    @Test
    void bindPrompt() {
        JsonNode c = v4.get("bindPrompt");
        assertEquals(c.get("expected").asText(), Bindings.prompt(c.get("prompt").asText()));
    }

    @Test
    void bindResponse() {
        JsonNode c = v4.get("bindResponse");
        assertEquals(c.get("expected").asText(),
                Bindings.response(c.get("resultHash").asText(), c.get("callId").asText()));
    }

    // --- The live and offline verifiers ---

    /** The policy's proof for {@code route}, from its token, or null for no proof. */
    static String proof(JsonNode policy, JsonNode route) {
        return route.isNull() ? null : Vectors.tokenText(policy.get("proofTokens").get(route.asText()));
    }

    /** A case's blocks as received: its token's text, or null where no token was received. */
    static String blocks(JsonNode c) {
        JsonNode token = c.get("blocksToken");
        return token.isNull() ? null : Vectors.tokenText(token);
    }

    /** A case's extension settings: its {@code actsOn}, and its {@code allowedExtensions}, null for unset. */
    static ExtensionSettings settings(JsonNode c) {
        JsonNode allowed = c.get("allowedExtensions");
        return ExtensionSettings.of(names(c.get("actsOn")), allowed.isNull() ? null : names(allowed));
    }

    private static Set<String> names(JsonNode array) {
        Set<String> out = new LinkedHashSet<>();
        array.forEach(n -> out.add(n.textValue()));
        return out;
    }

    static Keyring keyring(JsonNode names) {
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        names.properties().forEach(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(v4.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        return Keyring.of(keys);
    }

    /**
     * A member's {@code notAfter}, or {@code absent} where it gives none. It is read strictly, as the TypeScript
     * core's {@code currentAt} reads a window that is not an integer: the window must be an integral number that
     * fits a long, else it is never current. Such a value, 1.5 for one, is {@link Long#MIN_VALUE}, a window no clock
     * is within, never one truncated or rounded into range.
     */
    private static long window(JsonNode member, long absent) {
        if (!member.has("notAfter")) {
            return absent;
        }
        JsonNode n = member.get("notAfter");
        return n.isIntegralNumber() && n.canConvertToLong() ? n.longValue() : Long.MIN_VALUE;
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
        JsonNode p = v4.get("policies").get(policy);
        return new PinnedRoot(Base64Url.decode(p.get("root").asText()), p.get("rootId").asText(), notAfter);
    }

    private static Peer peer(JsonNode p) {
        return p.isNull() ? null : new Peer(p.get("svc").asText(), p.get("inst").asText());
    }

    /**
     * The expected hand-over: null, or one member per name acted on, each one {svc, items} per stamp. Built through
     * {@link HandOver}'s own constructor, from stamps that carry only their signer and blocks that name exactly the
     * extensions whose items are not null, so it is compared by value with what the verifier hands over.
     */
    static HandOver handOver(JsonNode h) {
        if (h.isNull()) {
            return null;
        }
        List<String> svcs = null;
        List<Map<String, List<String>>> items = new ArrayList<>();
        for (var e : h.properties()) {
            List<String> signers = new ArrayList<>();
            for (int i = 0; i < e.getValue().size(); i++) {
                JsonNode entry = e.getValue().get(i);
                signers.add(entry.get("svc").textValue());
                if (items.size() <= i) {
                    items.add(new LinkedHashMap<>());
                }
                if (!entry.get("items").isNull()) {
                    List<String> texts = new ArrayList<>();
                    entry.get("items").forEach(item -> texts.add(Vectors.text(item)));
                    items.get(i).put(e.getKey(), texts);
                }
            }
            assertTrue(svcs == null || svcs.equals(signers), "every name lists the same stamps");
            svcs = signers;
        }
        List<Stamp> stamps = new ArrayList<>();
        List<Block> blocks = new ArrayList<>();
        for (int i = 0; svcs != null && i < svcs.size(); i++) {
            stamps.add(new Stamp(svcs.get(i), "", "", 0, "", "", "", "", "", ""));
            blocks.add(Block.of(items.get(i), List.of()));
        }
        Set<String> actsOn = new LinkedHashSet<>();
        h.fieldNames().forEachRemaining(actsOn::add);
        return new HandOver(true, stamps, blocks, ExtensionSettings.of(actsOn, null));
    }

    @Test
    void verify() {
        JsonNode cases = v4.get("verify");
        assertTrue(cases != null && cases.size() > 0, "verify section");
        Set<ReasonCode> given = EnumSet.noneOf(ReasonCode.class);
        for (JsonNode c : cases) {
            VerifyResult got = replayLive(c);
            assertEquals(expectedLive(c), got, c.get("name").asText());
            given.add(got.reason());
        }
        assertTrue(given.containsAll(EnumSet.of(ReasonCode.EXTENSION_MISMATCH, ReasonCode.EXTENSION_NOT_ALLOWED,
                ReasonCode.EXTENSION_REQUIRED, ReasonCode.PEER_MISMATCH)), "the section reaches 9a to 10: " + given);
    }

    /** A live case run {@code uses} times against one nonce cache, each use by its peer; the last result. */
    private static VerifyResult replayLive(JsonNode c) {
        JsonNode policy = v4.get("policies").get(c.get("policy").asText());
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        long now = c.get("now").asLong();
        long policyNotAfter = c.get("policyNotAfter").asLong();
        // A live member always has a window: one without is never current.
        VerifierConfig cfg = new VerifierConfig(keyrings(c, policyNotAfter, Long.MIN_VALUE),
                roots(c, policyNotAfter, Long.MIN_VALUE), policyNotAfter, origins,
                c.get("sess").asText(), new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now,
                c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong(), settings(c));
        Verifier verifier = new Verifier(cfg);
        VerifyResult result = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            Peer peer = peer(c.has("peers") ? c.get("peers").get(i) : c.get("peer"));
            result = verifier.verify(new VerifyInput(Vectors.tokenText(c.get("chainToken")),
                    c.get("expectedBind").asText(), blocks(c), proof(policy, c.get("proofRoute")),
                    c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(), c.get("nonceKey").asText(),
                    peer));
        }
        return result;
    }

    private static VerifyResult expectedLive(JsonNode c) {
        JsonNode want = c.get("expected");
        return new VerifyResult(ReasonCode.valueOf(want.get("reason").asText()), want.get("suspectSvc").asText(),
                want.get("suspectInst").asText(), handOver(want.get("handOver")));
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
        return new OfflineInput(Vectors.tokenText(c.get("chainToken")), c.get("expectedBind").asText(), blocks(c),
                proof(policy, c.get("proofRoute")), c.get("receiver").asText(), c.get("receiverInRoute").asBoolean(),
                c.get("nonceKey").asText(), c.get("rid").asText(),
                t.isNull() ? null : new RecordedTimes(t.get("last").asLong(), run), c.get("prompt").asText());
    }

    /** The offline config a case gives: offline, a member without a window counts for every record. */
    static OfflineConfig offlineConfig(JsonNode c) {
        Set<String> origins = new LinkedHashSet<>();
        c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
        Set<String> seen = new LinkedHashSet<>();
        c.get("seen").forEach(k -> seen.add(k.asText()));
        return new OfflineConfig(keyrings(c, Long.MAX_VALUE, Long.MAX_VALUE), roots(c, Long.MAX_VALUE, Long.MAX_VALUE),
                origins, c.get("sess").asText(), seen, null, limit(c.get("runMaxAgeMs")), limit(c.get("callMaxAgeMs")),
                settings(c));
    }

    /** An age limit a case gives; {@code null} is a limit not configured. */
    private static Long limit(JsonNode n) {
        return n.isNull() ? null : n.asLong();
    }

    @Test
    void offline() {
        JsonNode cases = v4.get("offline");
        assertTrue(cases != null && cases.size() > 0, "offline section");
        for (JsonNode c : cases) {
            assertEquals(expectedOffline(c), replayOffline(c), c.get("name").asText());
        }
    }

    private static OfflineResult replayOffline(JsonNode c) {
        return OfflineVerifier.verify(offlineInput(c, policy(c)), offlineConfig(c));
    }

    private static OfflineResult expectedOffline(JsonNode c) {
        JsonNode want = c.get("expected");
        return new OfflineResult(ReasonCode.valueOf(want.get("reason").asText()), want.get("suspectSvc").asText(),
                want.get("suspectInst").asText(), handOver(want.get("handOver")));
    }

    /**
     * Each case is one record set: its calls in order against one set of spent nonce keys, each by the offline
     * verifier with the config its session gives ({@link RecordedSession#callConfig}), then limited to that session.
     */
    @Test
    void recordedCall() {
        JsonNode cases = v4.get("recordedCall");
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
                RecordedSession session = sessions.get(call.get("handshake").asInt());
                OfflineConfig cfg = session.callConfig(origins, records.spent(), limit(c.get("runMaxAgeMs")),
                        limit(c.get("callMaxAgeMs")), settings(c));
                assertNotNull(cfg, name + " call " + i + ": its session is attested");
                OfflineResult result = OfflineVerifier.verify(offlineInput(call, policy(call)), cfg);
                ReasonCode reason = RecordSet.callInSession(session, result.reason(),
                        call.get("recordedTs").get("last").asLong());
                JsonNode want = c.get("expected").get(i);
                assertEquals(ReasonCode.valueOf(want.get("reason").asText()), reason, name + " call " + i);
                outsideSession |= reason == ReasonCode.OUTSIDE_SESSION;
            }
        }
        assertTrue(outsideSession, "a case gives OUTSIDE_SESSION");
    }

    // --- The extension influence (the member influence) ---

    @Test
    void influenceEntries() {
        JsonNode cases = v4.get("influence").get("entries");
        assertEquals(17, cases.size(), "influence.entries");
        for (JsonNode c : cases) {
            assertEquals(c.get("reads").asBoolean(), reads(() -> InfluenceEntry.parse(Vectors.text(c.get("item")))),
                    c.get("name").asText());
        }
    }

    @Test
    void influenceLabels() {
        JsonNode cases = v4.get("influence").get("labels");
        assertEquals(9, cases.size(), "influence.labels");
        for (JsonNode c : cases) {
            assertEquals(c.get("reads").asBoolean(), reads(() -> ContentLabel.parse(Vectors.text(c.get("item")))),
                    c.get("name").asText());
        }
    }

    /** Whether {@code reader} reads its item: it throws IllegalArgumentException for one that does not. */
    private static boolean reads(Runnable reader) {
        try {
            reader.run();
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Test
    void influenceRule() {
        JsonNode cases = v4.get("influence").get("rule");
        assertEquals(13, cases.size(), "influence.rule");
        for (JsonNode c : cases) {
            List<InfluenceFact> facts = new ArrayList<>();
            for (JsonNode f : c.get("influence")) {
                facts.add(new InfluenceFact(InfluenceClass.fromWire(f.get("cls").asText()),
                        f.has("owner") ? f.get("owner").textValue() : null));
            }
            JsonNode owner = c.get("destinationOwner");
            assertEquals(c.get("refused").asBoolean(),
                    InfluenceRule.publicWriteRefused(facts, owner.isNull() ? null : owner.textValue()),
                    c.get("name").asText());
        }
    }

    /**
     * The cases whose {@code served} is empty, decided from the items handed on alone. Not replayed
     * (spec/README.md, Conformance): the cases whose {@code served} is not empty, which add the classes an MCP
     * server served in its session, so they belong to the MCP profile as well.
     */
    @Test
    void influenceRequest() {
        int replayed = 0;
        for (JsonNode c : v4.get("influence").get("request")) {
            if (!c.get("served").isEmpty()) {
                continue;
            }
            replayed++;
            List<StampItems> stamps = new ArrayList<>();
            for (JsonNode st : c.get("stamps")) {
                List<String> items = null;
                if (!st.get("items").isNull()) {
                    items = new ArrayList<>();
                    for (JsonNode item : st.get("items")) {
                        items.add(Vectors.text(item));
                    }
                }
                stamps.add(new StampItems(st.get("svc").textValue(), items));
            }
            JsonNode owner = c.get("destinationOwner");
            Influence.Decision got = Influence.decide(stamps, List.of(), c.get("write").asBoolean(),
                    owner.isNull() ? null : owner.textValue());
            JsonNode want = c.get("expected");
            JsonNode every = want.get("everyStampNames");
            String name = c.get("name").asText();
            assertEquals(ReasonCode.valueOf(want.get("reason").asText()), got.reason(), name);
            assertEquals(every.isNull() ? null : every.booleanValue(), got.everyStampNames(), name);
        }
        assertEquals(12, replayed, "influence.request cases whose served is empty");
    }

    /**
     * As {@link #recordedCall}, at a verifier that acts on influence: the items are read once the offline order
     * gives OK, before the call is held to its session's limits (verification.md, Offline verification, row 9).
     */
    @Test
    void influenceRecordedCall() {
        JsonNode cases = v4.get("influence").get("recordedCall");
        assertEquals(1, cases.size(), "influence.recordedCall");
        for (JsonNode c : cases) {
            String name = c.get("name").asText();
            assertTrue(settings(c).actsOn().contains(Influence.NAME), name + ": acts on influence");
            List<RecordedSession> sessions = new ArrayList<>();
            c.get("handshakes").forEach(h -> sessions.add(recordedSession(h)));
            RecordSet records = new RecordSet();
            Set<String> origins = new LinkedHashSet<>();
            c.get("allowedOrigins").forEach(o -> origins.add(o.asText()));
            List<ReasonCode> got = new ArrayList<>();
            for (JsonNode call : c.get("calls")) {
                RecordedSession session = sessions.get(call.get("handshake").asInt());
                OfflineConfig cfg = session.callConfig(origins, records.spent(), limit(c.get("runMaxAgeMs")),
                        limit(c.get("callMaxAgeMs")), settings(c));
                assertNotNull(cfg, name + ": its session is attested");
                OfflineResult result = OfflineVerifier.verify(offlineInput(call, policy(call)), cfg);
                got.add(Influence.recordedCallReason(result, session, call.get("recordedTs").get("last").asLong()));
            }
            List<ReasonCode> want = new ArrayList<>();
            c.get("expected").forEach(e -> want.add(ReasonCode.valueOf(e.get("reason").asText())));
            assertEquals(List.of(ReasonCode.OK, ReasonCode.INFLUENCE_MISMATCH, ReasonCode.INFLUENCE_MISMATCH,
                    ReasonCode.OUTSIDE_SESSION), want, name + ": the case this replay was written for");
            assertEquals(want, got, name);
        }
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
        for (JsonNode c : v4.get("verify")) {
            if (c.has("keyrings") || c.has("roots")) {
                continue; // already written as arrays: verify() replays it
            }
            for (boolean split : new boolean[] {false, true}) {
                assertEquals(expectedLive(c), replayLive(asArrays(c, c.get("policyNotAfter"), split)),
                        c.get("name").asText() + (split ? ", split" : ""));
            }
        }
        for (JsonNode c : v4.get("offline")) {
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

    static JsonNode caseNamed(String section, String name) {
        for (JsonNode c : v4.get(section)) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException(name);
    }

    static JsonNode policy(JsonNode c) {
        return v4.get("policies").get(c.get("policy").asText());
    }
}
