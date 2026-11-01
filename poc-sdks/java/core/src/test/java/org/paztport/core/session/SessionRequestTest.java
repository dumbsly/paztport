// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/** A session request read from the body it arrives in: strictly, from its wire bytes. */
class SessionRequestTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static SessionRequest request(boolean withRoot) {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        SignedRoot root = withRoot ? SignedRoot.sign(Crypto.sha256("r".getBytes(StandardCharsets.UTF_8)), "v1",
                NOT_AFTER, policy.getPrivate()) : null;
        return SessionRequest.of(root, pin, KeyringFile.sign(Map.of("payment", "payment-key"), pin, NOT_AFTER,
                policy.getPrivate()), Sessions.newNonce());
    }

    /** The request's members as the SDK reads them, for a test to alter and write back as its JCS text. */
    private static Map<String, JsonValue> members(SessionRequest req) {
        return new LinkedHashMap<>(((JsonValue.Obj) JsonReader.wireText(req.toJson())).members());
    }

    private static String text(Map<String, JsonValue> members) {
        return JsonWriter.text(new JsonValue.Obj(members));
    }

    @Test
    void parsesRequestJson() {
        SessionRequest req = request(true);

        assertEquals(req, SessionRequest.parse(req.toJson().getBytes(StandardCharsets.UTF_8)));
        assertEquals(req, SessionRequest.parse(req.toJson()));
    }

    /**
     * A body is read as the request's wire bytes, as they are: UTF-16, UTF-8 behind a byte order mark, whitespace
     * around it or a second value after it, and the same request in another member order, are not those bytes.
     */
    @Test
    void refusesAnythingButTheRequestsWireBytes() {
        String json = request(true).toJson();
        int nonce = json.lastIndexOf(",\"nonce\":");
        String nonceFirst = "{" + json.substring(nonce + 1, json.length() - 1) + "," + json.substring(1, nonce) + "}";
        for (byte[] body : List.of(json.getBytes(StandardCharsets.UTF_16BE),
                ("\uFEFF" + json).getBytes(StandardCharsets.UTF_8), (json + "\n").getBytes(StandardCharsets.UTF_8),
                (" " + json).getBytes(StandardCharsets.UTF_8), (json + " {}").getBytes(StandardCharsets.UTF_8),
                nonceFirst.getBytes(StandardCharsets.UTF_8))) {
            assertThrows(MalformedJsonException.class, () -> SessionRequest.parse(body));
        }
    }

    @Test
    void refusesNonJsonAndTrailing() {
        for (String body : new String[] {"{", "{} {}", "[]", "null"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> SessionRequest.parse(body.getBytes(StandardCharsets.UTF_8)), body);
        }
        assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse((byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse((String) null));
    }

    @Test
    void aMissingKeyringSignatureIsMalformed() {
        Map<String, JsonValue> wire = members(request(false));

        wire.remove("clientKeyringSig");
        assertEquals("no member clientKeyringSig", assertThrows(IllegalArgumentException.class,
                () -> SessionRequest.parse(text(wire))).getMessage());
        for (JsonValue bad : List.of(new JsonValue.Null(), new JsonValue.Int(7))) {
            Map<String, JsonValue> o = new LinkedHashMap<>(wire);
            o.put("clientKeyringSig", bad);
            assertEquals("member clientKeyringSig is not a string", assertThrows(IllegalArgumentException.class,
                    () -> SessionRequest.parse(text(o))).getMessage(), bad.toString());
        }
        wire.put("clientKeyringSig", new JsonValue.Str(""));
        assertEquals("member clientKeyringSig is empty", assertThrows(IllegalArgumentException.class,
                () -> SessionRequest.parse(text(wire))).getMessage());
    }

    @Test
    void anEmptyKeyringSignatureIsRefusedWhenBuilt() {
        Map<String, String> ring = Map.of("payment", "payment-key");
        assertThrows(IllegalArgumentException.class,
                () -> new SessionRequest(null, "pin", ring, "", NOT_AFTER, "nonce"));
        assertThrows(NullPointerException.class,
                () -> new SessionRequest(null, "pin", ring, null, NOT_AFTER, "nonce"));
        assertThrows(NullPointerException.class, () -> SessionRequest.of(null, "pin",
                new KeyringFile(ring, "pin", null, NOT_AFTER), "nonce"), "an unsigned keyring");
    }

    /**
     * Client material without {@code notAfter} is malformed: a request whose keyring window or client root window is
     * missing is refused when read, as one whose window is not an integer is, and so opens no session at all.
     */
    @Test
    void clientMaterialWithoutNotAfterIsMalformed() {
        Map<String, JsonValue> wire = members(request(true));

        Map<String, JsonValue> noRingWindow = new LinkedHashMap<>(wire);
        noRingWindow.remove("clientKeyringNotAfter");
        assertEquals("no member clientKeyringNotAfter", assertThrows(IllegalArgumentException.class,
                () -> SessionRequest.parse(text(noRingWindow))).getMessage());
        Map<String, JsonValue> root = new LinkedHashMap<>(((JsonValue.Obj) wire.get("clientRoot")).members());
        root.remove("notAfter");
        Map<String, JsonValue> noRootWindow = new LinkedHashMap<>(wire);
        noRootWindow.put("clientRoot", new JsonValue.Obj(root));
        assertEquals("no member notAfter", assertThrows(IllegalArgumentException.class,
                () -> SessionRequest.parse(text(noRootWindow))).getMessage());
    }
}
