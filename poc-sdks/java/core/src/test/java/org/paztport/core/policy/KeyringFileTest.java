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

    private static KeyringFile newForm() {
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
        assertFalse(new KeyringFile(Map.of("pi", pub(OTHER)), pub(POLICY), null).verifies(pub(POLICY)));
    }

    @Test
    void garbageSigDoesNotThrow() {
        assertFalse(new KeyringFile(Map.of(), pub(POLICY), "!!").verifies(pub(POLICY)));
    }

    @Test
    void jsonWithAndWithoutSigDeserialises() throws Exception {
        ObjectMapper m = new ObjectMapper();
        KeyringFile f = signed();
        assertEquals(f, m.readValue(m.writeValueAsBytes(f), KeyringFile.class));
        KeyringFile bare = m.readValue("{\"services\":{},\"policy\":\"p\"}", KeyringFile.class);
        assertNull(bare.sig());
        assertFalse(m.writeValueAsString(bare).contains("sig"));
    }

    @Test
    void sigTextIsNotHeldToCanonicalEncoding() {
        KeyringFile f = signed();
        assertTrue(new KeyringFile(f.services(), f.policy(), f.sig() + "==", f.notAfter()).verifies(pub(POLICY)));
    }

    @Test
    void newFormSignsTheWindowUnderTheSamePrefix() {
        assertEquals("paztport-keyring\n{\"notAfter\":1798761600000,\"policy\":\"P\",\"services\":{\"a\":\"K\"}}",
                new String(KeyringFile.signingBytes("P", Map.of("a", "K"), NOT_AFTER), StandardCharsets.UTF_8));
        assertEquals("paztport-keyring\n{\"notAfter\":9007199254740991,\"policy\":\"P\",\"services\":{}}",
                new String(KeyringFile.signingBytes("P", Map.of(), MAX_SAFE), StandardCharsets.UTF_8));
        assertEquals("paztport-keyring\n{\"policy\":\"P\",\"services\":{\"a\":\"K\"}}",
                new String(KeyringFile.signingBytes("P", Map.of("a", "K")), StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.signingBytes("P", Map.of(), -1));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.signingBytes("P", Map.of(), MAX_SAFE + 1));
    }

    @Test
    void newFormRoundTrip() throws Exception {
        KeyringFile f = newForm();
        assertTrue(f.isNewForm());
        assertEquals(NOT_AFTER, f.notAfter());
        assertEquals(SERVICES, f.services());
        assertTrue(f.verifies(pub(POLICY)));
        assertFalse(f.verifies(pub(OTHER)));
        KeyringFile parsed = KeyringFile.parse(JSON.valueToTree(f));
        assertEquals(f, parsed);
        assertTrue(parsed.verifies(pub(POLICY)));
        // The readers that still bind the record keep the window.
        assertEquals(f, JSON.readValue(JSON.writeValueAsBytes(f), KeyringFile.class));
    }

    @Test
    void newFormTamperedNotAfterFails() {
        KeyringFile f = newForm();
        assertFalse(new KeyringFile(f.services(), f.policy(), f.sig(), NOT_AFTER + 1).verifies(pub(POLICY)));
    }

    @Test
    void newFormTamperedServiceFails() {
        KeyringFile f = newForm();
        assertFalse(new KeyringFile(Map.of("pi", pub(OTHER)), f.policy(), f.sig(), f.notAfter())
                .verifies(pub(POLICY)));
    }

    @Test
    void neitherFormPassesForTheOther() {
        KeyringFile f = newForm();
        assertFalse(new KeyringFile(f.services(), f.policy(), f.sig()).verifies(pub(POLICY)),
                "dropping notAfter must not turn a new-form signature into an old-form one");
        KeyringFile old = KeyringFile.signOldForm(SERVICES, pub(POLICY), POLICY.getPrivate());
        assertFalse(new KeyringFile(old.services(), old.policy(), old.sig(), NOT_AFTER).verifies(pub(POLICY)),
                "adding notAfter must not lend an old-form signature a window it never signed");
    }

    @Test
    void oldFormStillVerifies() throws Exception {
        KeyringFile old = KeyringFile.signOldForm(SERVICES, pub(POLICY), POLICY.getPrivate());
        assertFalse(old.isNewForm());
        assertNull(old.notAfter());
        assertTrue(old.verifies(pub(POLICY)));
        assertFalse(JSON.writeValueAsString(old).contains("notAfter"));
        KeyringFile parsed = KeyringFile.parse(json(JSON.writeValueAsString(old)));
        assertEquals(old, parsed);
        assertTrue(parsed.verifies(pub(POLICY)));
    }

    @Test
    void currentAtNotAfterNotAfter() {
        KeyringFile f = newForm();
        assertTrue(f.isCurrent(NOT_AFTER));
        assertFalse(f.isCurrent(NOT_AFTER + 1));
        assertFalse(KeyringFile.signOldForm(SERVICES, pub(POLICY), POLICY.getPrivate()).isCurrent(0));
    }

    @Test
    void renewedKeepsServicesAndPolicy() {
        KeyringFile old = KeyringFile.signOldForm(SERVICES, pub(POLICY), POLICY.getPrivate());
        KeyringFile renewed = old.renewed(NOT_AFTER + 5, POLICY.getPrivate());
        assertEquals(old.services(), renewed.services());
        assertEquals(old.policy(), renewed.policy());
        assertEquals(NOT_AFTER + 5, renewed.notAfter());
        assertTrue(renewed.verifies(pub(POLICY)));
    }

    @Test
    void notAfterByValue() throws Exception {
        KeyringFile f = newForm();
        String head = "{\"services\":" + JSON.writeValueAsString(SERVICES) + ",\"policy\":\"" + f.policy()
                + "\",\"sig\":\"" + f.sig() + "\",\"notAfter\":";
        assertEquals(1_000_000_000_000L, KeyringFile.parse(json(head + "1.0e12}")).notAfter());
        assertEquals(MAX_SAFE, KeyringFile.parse(json(head + MAX_SAFE + "}")).notAfter());
        assertEquals(0L, KeyringFile.parse(json(head + "0}")).notAfter());
        assertTrue(KeyringFile.parse(json(head + "1798761600000.0}")).verifies(pub(POLICY)));
        for (String bad : new String[] {"1.5", "-1", String.valueOf(MAX_SAFE + 1), "\"1798761600000\"", "null",
                "true", "{}", "[]"}) {
            assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(json(head + bad + "}")), bad);
        }
    }

    @Test
    void parseRefusesAMalformedKeyring() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(null));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(json("[]")));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(json("{\"policy\":\"p\"}")));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse(json("{\"services\":{\"a\":1},\"policy\":\"p\"}")));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse(json("{\"services\":[],\"policy\":\"p\"}")));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(json("{\"services\":{}}")));
        assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse(json("{\"services\":{},\"policy\":\"p\",\"sig\":7}")));
        // An unsigned file has no sig; an unsigned field is ignored.
        assertNull(KeyringFile.parse(json("{\"services\":{},\"policy\":\"p\"}")).sig());
        ObjectNode extra = JSON.valueToTree(newForm());
        extra.put("note", "unsigned");
        assertTrue(KeyringFile.parse(extra).verifies(pub(POLICY)));
    }

    @Test
    void loadReadsTheFileStrictly(@TempDir Path dir) throws Exception {
        KeyringFile f = newForm();
        Path file = dir.resolve("keyring.json");
        Files.write(file, JSON.writeValueAsBytes(f));
        assertEquals(f, KeyringFile.load(file));
        Files.writeString(file, "{\"services\":{},\"policy\":\"p\",\"notAfter\":1.5}");
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
        Files.writeString(file, "{not json");
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
    }

    @Test
    void newFormGarbageNeverThrows() {
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), "!!", NOT_AFTER).verifies(pub(POLICY)));
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), newForm().sig(), -1L).verifies(pub(POLICY)));
    }
}
