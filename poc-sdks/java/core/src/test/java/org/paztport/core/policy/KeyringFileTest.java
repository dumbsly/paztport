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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.encoding.MalformedJsonException.Step;

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
    void aSignedKeyringRoundTripsAndAFileWithoutASigIsRefused() {
        KeyringFile f = signed();
        assertEquals(f, KeyringFile.parse(f.toJson()));
        KeyringFile bare = new KeyringFile(Map.of(), "p", null, 1);
        assertNull(bare.sig());
        assertEquals("{\"notAfter\":1,\"policy\":\"p\",\"services\":{}}", bare.toJson());
        assertEquals("no member sig",
                assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(bare.toJson())).getMessage());
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
    void notAfterIsAProtocolInteger() throws Exception {
        KeyringFile f = signedRing();
        String head = "{\"services\":" + JSON.writeValueAsString(SERVICES) + ",\"policy\":\"" + f.policy()
                + "\",\"sig\":\"" + f.sig() + "\",\"notAfter\":";
        assertEquals(MAX_SAFE, KeyringFile.parse(head + MAX_SAFE + "}").notAfter());
        assertEquals(0L, KeyringFile.parse(head + "0}").notAfter());
        assertTrue(KeyringFile.parse(head + NOT_AFTER + "}").verifies(pub(POLICY)));
        for (String bad : new String[] {"1.0e12", "1798761600000.0", "1.5", "-1", String.valueOf(MAX_SAFE + 1),
                "\"1798761600000\"", "null", "true", "{}", "[]"}) {
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
                () -> KeyringFile.parse("{\"services\":{},\"policy\":\"p\",\"sig\":7,\"notAfter\":1}"));
    }

    /** Each refusal names the member at fault: a service key that is not a string names {@code services}. */
    @Test
    void aServiceKeyThatIsNotAStringNamesServices() {
        String text = "{\"notAfter\":1,\"policy\":\"p\",\"services\":{\"pi\":1},\"sig\":\"s\"}";
        assertEquals("member services holds a value that is not a string",
                assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(text)).getMessage());
        assertEquals("member services is not an object", assertThrows(IllegalArgumentException.class,
                () -> KeyringFile.parse(text.replace("{\"pi\":1}", "[]"))).getMessage());
    }

    /** A service's name is data, checked by the route-node rule, and the refusal does not repeat it. */
    @Test
    void aServiceNameThatIsNotARouteNodeIsMalformed() {
        for (String name : new String[] {"", ".", "..", "a/b", "a\\b", "a|b"}) {
            Map<String, String> services = Map.of(name, SERVICES.get("pi"));
            String sig = Base64Url.encode(Crypto.sign(POLICY.getPrivate(),
                    KeyringFile.signingBytes(pub(POLICY), services, NOT_AFTER)));
            String text = new KeyringFile(services, pub(POLICY), sig, NOT_AFTER).toFile();
            assertEquals("member services holds a name that is not a route node",
                    assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(text), name).getMessage());
        }
    }

    /** The writer refuses what every reader refuses, before it signs. */
    @Test
    void signRefusesAServiceNameThatIsNotARouteNode() {
        for (String name : new String[] {"", ".", "..", "a/b", "a\\b", "a|b"}) {
            String message = assertThrows(IllegalArgumentException.class, () -> KeyringFile.sign(
                    Map.of(name, SERVICES.get("pi")), pub(POLICY), NOT_AFTER, POLICY.getPrivate()), name).getMessage();
            assertTrue(message.contains("route node"), message);
        }
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
        assertEquals("no member notAfter", e.getMessage());
        Path file = dir.resolve("keyring.json");
        Files.writeString(file, text);
        e = assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file));
        assertEquals("no member notAfter", e.getMessage());
    }

    /**
     * A file is read in any member order and spacing: here as Jackson's pretty printer writes one, members in the
     * record's order, {@code " : "} between a name and its value, and no newline at the end.
     */
    @Test
    void aFileInAnyMemberOrderAndSpacingLoads(@TempDir Path dir) throws Exception {
        KeyringFile f = signedRing();
        String text = "{\n  \"services\" : {\n    \"pi\" : \"" + SERVICES.get("pi") + "\"\n  },\n  \"policy\" : \""
                + f.policy() + "\",\n  \"sig\" : \"" + f.sig() + "\",\n  \"notAfter\" : " + NOT_AFTER + "\n}";
        Path file = dir.resolve("keyring.json");
        Files.writeString(file, text);
        assertEquals(f, KeyringFile.load(file));
        assertEquals(f, KeyringFile.parse(text));
    }

    /** A {@code notAfter} is a protocol integer by its text: {@code 1798761600000.0} does not read, though equal. */
    @Test
    void aNotAfterWrittenWithAFractionIsMalformed(@TempDir Path dir) throws Exception {
        String text = signedRing().toFile().replace(NOT_AFTER + ",", NOT_AFTER + ".0,");
        assertTrue(text.contains("1798761600000.0"), text);
        Path file = dir.resolve("keyring.json");
        Files.writeString(file, text);
        assertEquals(Step.PARSE, assertThrows(MalformedJsonException.class, () -> KeyringFile.load(file)).step());
        assertEquals(Step.PARSE, assertThrows(MalformedJsonException.class, () -> KeyringFile.parse(text)).step());
    }

    /** A member the keyring does not define is refused, not ignored. */
    @Test
    void anExtraMemberIsMalformed(@TempDir Path dir) throws Exception {
        String text = signedRing().toFile().replace("{\n", "{\n  \"note\": \"not signed\",\n");
        Path file = dir.resolve("keyring.json");
        Files.writeString(file, text);
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(file)).getMessage());
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> KeyringFile.parse(text)).getMessage());
    }

    @Test
    void garbageNeverThrows() {
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), "!!", NOT_AFTER).verifies(pub(POLICY)));
        assertFalse(new KeyringFile(SERVICES, pub(POLICY), signedRing().sig(), -1L).verifies(pub(POLICY)));
    }
}
