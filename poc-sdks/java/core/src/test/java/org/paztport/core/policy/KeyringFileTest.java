// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class KeyringFileTest {

    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair OTHER = Crypto.generateEd25519KeyPair();

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long NOT_AFTER = 1_798_761_600_000L;
    private static final long MAX_SAFE = (1L << 53) - 1;
    private static final Map<String, String> SERVICES = Map.of("pi", pub(Crypto.generateEd25519KeyPair()));

    private static KeyringFile signedRing() {
        return KeyringFile.sign(SERVICES, pub(POLICY), NOT_AFTER, POLICY.getPrivate());
    }

    private static JsonNode json(String text) throws Exception {
        return JSON.readTree(text);
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static KeyringFile signed() {
        return KeyringFile.sign(Map.of("pi", pub(Crypto.generateEd25519KeyPair())), pub(POLICY), NOT_AFTER,
                POLICY.getPrivate());
    }

    @Test
    void verifiesUnderItsOwnPolicyKey() {
        assertTrue(signed().verifies(pub(POLICY)));
    }

    @Test
    void failsUnderAnotherKey() {
        assertFalse(signed().verifies(pub(OTHER)));
    }

    @Test
    void failsWithOneServiceKeyChanged() {
        KeyringFile f = signed();
        KeyringFile tampered = new KeyringFile(Map.of("pi", pub(OTHER)), f.policy(), f.sig(), f.notAfter());
        assertFalse(tampered.verifies(pub(POLICY)));
    }

    @Test
    void unsignedNeverVerifies() {
        assertFalse(new KeyringFile(Map.of("pi", pub(OTHER)), pub(POLICY), null, NOT_AFTER).verifies(pub(POLICY)));
    }

    @Test
    void garbageSigDoesNotThrow() {
        assertFalse(new KeyringFile(Map.of(), pub(POLICY), "!!", NOT_AFTER).verifies(pub(POLICY)));
    }

    @Test
    void jsonWithAndWithoutSigDeserialises() throws Exception {
        ObjectMapper m = new ObjectMapper();
        KeyringFile f = signed();
        assertEquals(f, m.readValue(m.writeValueAsBytes(f), KeyringFile.class));
        KeyringFile bare = m.readValue("{\"services\":{},\"policy\":\"p\",\"notAfter\":1}", KeyringFile.class);
        assertNull(bare.sig());
        assertFalse(m.writeValueAsString(bare).contains("sig"));
    }

    @Test
    void sigTextMustBeCanonicalEncoding() {
        KeyringFile f = signed();
        assertFalse(new KeyringFile(f.services(), f.policy(), f.sig() + "==", f.notAfter()).verifies(pub(POLICY)));
    }

    @Test
    void signsTheWindowUnderTheDomainPrefix() {
        assertEquals("paztport-keyring\n{\"notAfter\":1798761600000,\"policy\":\"P\",\"services\":{\"a\":\"K\"}}",
                new String(KeyringFile.signingBytes("P", Map.of("a", "K"), NOT_AFTER), StandardCharsets.UTF_8));
        assertEquals("paztport-keyring\n{\"notAfter\":9007199254740991,\"policy\":\"P\",\"services\":{}}",
                new String(KeyringFile.signingBytes("P", Map.of(), MAX_SAFE), StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.signingBytes("P", Map.of(), -1));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.signingBytes("P", Map.of(), MAX_SAFE + 1));
    }

    @Test
    void roundTrip() throws Exception {
        KeyringFile f = signedRing();
        assertEquals(NOT_AFTER, f.notAfter());
        assertEquals(SERVICES, f.services());
        assertTrue(f.verifies(pub(POLICY)));
        assertFalse(f.verifies(pub(OTHER)));
        KeyringFile parsed = KeyringFile.parse(f.toJson());
        assertEquals(f, parsed);
        assertTrue(parsed.verifies(pub(POLICY)));
        // The readers that still bind the record keep the window.
        assertEquals(f, JSON.readValue(JSON.writeValueAsBytes(f), KeyringFile.class));
    }

    @Test
    void tamperedNotAfterFails() {
        KeyringFile f = signedRing();
        assertFalse(new KeyringFile(f.services(), f.policy(), f.sig(), NOT_AFTER + 1).verifies(pub(POLICY)));
    }

    @Test
    void tamperedServiceFails() {
        KeyringFile f = signedRing();
        assertFalse(new KeyringFile(Map.of("pi", pub(OTHER)), f.policy(), f.sig(), f.notAfter())
                .verifies(pub(POLICY)));
    }

    @Test
    void aSignatureOverTheServicesAndPolicyKeyAloneFails() {
        String body = "{\"policy\":\"" + pub(POLICY) + "\",\"services\":{\"pi\":\"" + SERVICES.get("pi") + "\"}}";
        String sig = Base64Url.encode(Crypto.sign(POLICY.getPrivate(),
                ("paztport-keyring\n" + body).getBytes(StandardCharsets.UTF_8)));
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), sig, NOT_AFTER).verifies(pub(POLICY)),
                "a window must not be lent to a signature that never covered one");
    }

    @Test
    void currentAtNotAfterNotAfter() {
        KeyringFile f = signedRing();
        assertTrue(f.isCurrent(NOT_AFTER));
        assertFalse(f.isCurrent(NOT_AFTER + 1));
    }

    @Test
    void renewedKeepsServicesAndPolicy() {
        KeyringFile old = KeyringFile.sign(SERVICES, pub(POLICY), 1000, POLICY.getPrivate());
        KeyringFile renewed = old.renewed(NOT_AFTER + 5, POLICY.getPrivate());
        assertEquals(old.services(), renewed.services());
        assertEquals(old.policy(), renewed.policy());
        assertEquals(NOT_AFTER + 5, renewed.notAfter());
        assertTrue(renewed.verifies(pub(POLICY)));
    }

    @Test
    void notAfterByValue() throws Exception {
        KeyringFile f = signedRing();
        String head = "{\"services\":" + JSON.writeValueAsString(SERVICES) + ",\"policy\":\"" + f.policy()
                + "\",\"sig\":\"" + f.sig() + "\",\"notAfter\":";
        assertEquals(1_000_000_000_000L, KeyringFile.parse(head + "1.0e12}").notAfter());
        assertEquals(MAX_SAFE, KeyringFile.parse(head + MAX_SAFE + "}").notAfter());
        assertEquals(0L, KeyringFile.parse(head + "0}").notAfter());
        assertTrue(KeyringFile.parse(head + "1798761600000.0}").verifies(pub(POLICY)));
        for (String bad : new String[] {"1.5", "-1", String.valueOf(MAX_SAFE + 1), "\"1798761600000\"", "null",
                "true", "{}", "[]"}) {
            assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(head + bad + "}"), bad);
        }
    }

    @Test
    void parseRefusesAMalformedKeyring() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(null));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse("[]"));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse("{\"policy\":\"p\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse("{\"services\":{\"a\":1},\"policy\":\"p\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse("{\"services\":[],\"policy\":\"p\"}"));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse("{\"services\":{}}"));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse("{\"services\":{},\"policy\":\"p\",\"sig\":7}"));
        // An unsigned file has no sig; an unsigned field is ignored.
        assertNull(KeyringFile.parse("{\"services\":{},\"policy\":\"p\",\"notAfter\":1}").sig());
        ObjectNode extra = JSON.valueToTree(signedRing());
        extra.put("note", "unsigned");
        assertTrue(KeyringFile.parse(extra.toString()).verifies(pub(POLICY)));
    }

    @Test
    void loadReadsTheFileStrictly(@TempDir Path dir) throws Exception {
        KeyringFile f = signedRing();
        Path file = dir.resolve("keyring.json");
        Files.write(file, JSON.writeValueAsBytes(f));
        assertEquals(f, KeyringFile.load(file));
        Files.writeString(file, "{\"services\":{},\"policy\":\"p\",\"notAfter\":1.5}");
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
        Files.writeString(file, "{not json");
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
    }

    /**
     * A keyring without {@code notAfter} is malformed, read from text or from a file, with the answer a
     * {@code notAfter} that is not an integer gets. Its signature is over the services and policy key alone, so it
     * would verify were the reader to take the missing window for none.
     */
    @Test
    void aKeyringWithoutNotAfterIsRefused(@TempDir Path dir) throws Exception {
        String body = "{\"policy\":\"" + pub(POLICY) + "\",\"services\":{\"pi\":\"" + SERVICES.get("pi") + "\"}}";
        String sig = Base64Url.encode(Crypto.sign(POLICY.getPrivate(),
                ("paztport-keyring\n" + body).getBytes(StandardCharsets.UTF_8)));
        String text = body.substring(0, body.length() - 1) + ",\"sig\":\"" + sig + "\"}";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(text));
        assertEquals("keyring notAfter must be an integer in [0, 2^53 - 1]", e.getMessage());
        Path file = dir.resolve("keyring.json");
        Files.writeString(file, text);
        e = assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
        assertEquals("keyring notAfter must be an integer in [0, 2^53 - 1]", e.getMessage());
    }

    @Test
    void garbageNeverThrows() {
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), "!!", NOT_AFTER).verifies(pub(POLICY)));
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), signedRing().sig(), -1L).verifies(pub(POLICY)));
    }
}
