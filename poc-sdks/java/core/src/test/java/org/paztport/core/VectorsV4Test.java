// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.offline.RecordedSession;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.Requirement;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Block;

/** Replays {@code spec/vectors/v4.json}. */
class VectorsV4Test {

    private static JsonNode v4;

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
                VectorsV3Test.refused(c);
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
}
