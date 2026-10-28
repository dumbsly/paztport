// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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

class SignedRootTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final long NOT_AFTER = 1_798_761_600_000L;
    private static final long MAX_SAFE = (1L << 53) - 1;
    private static final byte[] ROOT = Crypto.sha256("root".getBytes(StandardCharsets.UTF_8));

    private static SignedRoot newForm() {
        return SignedRoot.sign(ROOT, "v1", NOT_AFTER, POLICY.getPrivate());
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static JsonNode json(String text) throws Exception {
        return JSON.readTree(text);
    }

    @Test
    void signedRootVerifiesWithPolicyPublicKey() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        byte[] root = Crypto.sha256("root".getBytes());

        SignedRoot signed = SignedRoot.sign(root, "v1", policy.getPrivate());

        assertTrue(signed.verify(policy.getPublic()));
        assertArrayEquals(root, signed.rootBytes());
        assertEquals("v1", signed.rootId());
    }

    @Test
    void verifyFailsWithWrongPolicyKey() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair attacker = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        assertFalse(signed.verify(attacker.getPublic()));
    }

    @Test
    void verifyFailsWhenRootTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot forged = new SignedRoot(
                signed.rootId(), Base64Url.encode(Crypto.sha256("evil".getBytes())), signed.sig());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void verifyFailsWhenRootIdTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot forged = new SignedRoot("v2", signed.root(), signed.sig());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void encodeDecodeRoundTrips() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", policy.getPrivate());

        SignedRoot decoded = SignedRoot.decode(signed.encode());
        assertEquals(signed, decoded);
        assertTrue(decoded.verify(policy.getPublic()));
    }

    @Test
    void newFormSignsUnderItsOwnDomainPrefix() {
        assertEquals("paztport-root\n{\"notAfter\":1798761600000,\"root\":\"R\",\"rootId\":\"v1\"}",
                new String(SignedRoot.signingBytes("v1", "R", NOT_AFTER), StandardCharsets.UTF_8));
        assertEquals("paztport-root\n{\"notAfter\":9007199254740991,\"root\":\"R\",\"rootId\":\"v1\"}",
                new String(SignedRoot.signingBytes("v1", "R", MAX_SAFE), StandardCharsets.UTF_8));
        assertEquals("v1|R", new String(SignedRoot.signingBytes("v1", "R"), StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.signingBytes("v1", "R", -1));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.signingBytes("v1", "R", MAX_SAFE + 1));
    }

    @Test
    void newFormRoundTrip() throws Exception {
        SignedRoot r = newForm();
        assertTrue(r.isNewForm());
        assertEquals(NOT_AFTER, r.notAfter());
        assertEquals("v1", r.rootId());
        assertArrayEquals(ROOT, r.rootBytes());
        assertTrue(r.verify(POLICY.getPublic()));
        assertFalse(r.verify(Crypto.generateEd25519KeyPair().getPublic()));

        SignedRoot parsed = SignedRoot.parse(JSON.valueToTree(r));
        assertEquals(r, parsed);
        assertTrue(parsed.verify(POLICY.getPublic()));
        assertEquals(r, SignedRoot.decode(r.encode()));
        // The readers that still bind the record keep the window.
        assertEquals(r, JSON.readValue(JSON.writeValueAsBytes(r), SignedRoot.class));
    }

    @Test
    void tamperedNotAfterFails() {
        SignedRoot r = newForm();
        assertFalse(new SignedRoot(r.rootId(), r.root(), r.sig(), NOT_AFTER + 1).verify(POLICY.getPublic()));
    }

    @Test
    void neitherFormPassesForTheOther() {
        SignedRoot r = newForm();
        assertFalse(new SignedRoot(r.rootId(), r.root(), r.sig()).verify(POLICY.getPublic()),
                "dropping notAfter must not turn a new-form signature into an old-form one");
        SignedRoot old = SignedRoot.sign(ROOT, "v1", POLICY.getPrivate());
        assertFalse(new SignedRoot(old.rootId(), old.root(), old.sig(), NOT_AFTER).verify(POLICY.getPublic()),
                "adding notAfter must not lend an old-form signature a window it never signed");
    }

    @Test
    void newFormTamperedRootOrRootIdFails() {
        SignedRoot r = newForm();
        assertFalse(new SignedRoot("v2", r.root(), r.sig(), r.notAfter()).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot(r.rootId(), Base64Url.encode(Crypto.sha256("evil".getBytes())), r.sig(),
                r.notAfter()).verify(POLICY.getPublic()));
    }

    @Test
    void oldFormStillVerifies() throws Exception {
        SignedRoot old = SignedRoot.sign(ROOT, "v1", POLICY.getPrivate());
        assertFalse(old.isNewForm());
        assertNull(old.notAfter());
        assertTrue(old.verify(POLICY.getPublic()));
        // An old-form root written today carries no notAfter at all, not a null one.
        assertFalse(JSON.writeValueAsString(old).contains("notAfter"));
        SignedRoot parsed = SignedRoot.parse(json(JSON.writeValueAsString(old)));
        assertEquals(old, parsed);
        assertTrue(parsed.verify(POLICY.getPublic()));
    }

    @Test
    void currentAtNotAfterNotAfter() {
        SignedRoot r = newForm();
        assertTrue(r.isCurrent(NOT_AFTER - 1));
        assertTrue(r.isCurrent(NOT_AFTER));
        assertFalse(r.isCurrent(NOT_AFTER + 1));
        SignedRoot old = SignedRoot.sign(ROOT, "v1", POLICY.getPrivate());
        assertFalse(old.isCurrent(0));
        assertFalse(old.isCurrent(Long.MIN_VALUE));
    }

    @Test
    void renewedKeepsRootAndRootId() {
        SignedRoot old = SignedRoot.sign(ROOT, "v1", POLICY.getPrivate());
        SignedRoot renewed = old.renewed(NOT_AFTER + 5, POLICY.getPrivate());
        assertEquals(old.rootId(), renewed.rootId());
        assertEquals(old.root(), renewed.root());
        assertEquals(NOT_AFTER + 5, renewed.notAfter());
        assertTrue(renewed.isNewForm());
        assertTrue(renewed.verify(POLICY.getPublic()));
        SignedRoot again = newForm().renewed(NOT_AFTER + 9, POLICY.getPrivate());
        assertEquals(NOT_AFTER + 9, again.notAfter());
        assertTrue(again.verify(POLICY.getPublic()));
    }

    @Test
    void notAfterByValue() throws Exception {
        SignedRoot r = newForm();
        String head = "{\"rootId\":\"v1\",\"root\":\"" + r.root() + "\",\"sig\":\"" + r.sig() + "\",\"notAfter\":";
        assertEquals(1_000_000_000_000L, SignedRoot.parse(json(head + "1.0e12}")).notAfter());
        assertEquals(MAX_SAFE, SignedRoot.parse(json(head + MAX_SAFE + "}")).notAfter());
        assertEquals(0L, SignedRoot.parse(json(head + "0}")).notAfter());
        assertTrue(SignedRoot.parse(json(head + "1798761600000.0}")).verify(POLICY.getPublic()));
        for (String bad : new String[] {"1.5", "-1", String.valueOf(MAX_SAFE + 1), "\"1798761600000\"", "null",
                "true", "{}", "[]"}) {
            assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(json(head + bad + "}")), bad);
        }
    }

    @Test
    void parseRefusesAMalformedRoot() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(null));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(json("[]")));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse(json("{\"root\":\"R\",\"sig\":\"S\"}")));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse(json("{\"rootId\":1,\"root\":\"R\",\"sig\":\"S\"}")));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse(json("{\"rootId\":\"v1\",\"root\":\"R\"}")));
        // An unsigned field is ignored, as on a reply certificate.
        SignedRoot r = newForm();
        ObjectNode extra = JSON.valueToTree(r);
        extra.put("note", "unsigned");
        assertTrue(SignedRoot.parse(extra).verify(POLICY.getPublic()));
    }

    @Test
    void loadReadsTheFileStrictly(@TempDir Path dir) throws Exception {
        SignedRoot r = newForm();
        Path file = dir.resolve("root.json");
        Files.write(file, JSON.writeValueAsBytes(r));
        assertEquals(r, SignedRoot.load(file));
        Files.writeString(file, "{\"rootId\":\"v1\",\"root\":\"R\",\"sig\":\"S\",\"notAfter\":1.5}");
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file));
        Files.writeString(file, "{not json");
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file));
    }

    @Test
    void verifyNeverThrows() {
        assertFalse(new SignedRoot("v1", "R", "!!").verify(POLICY.getPublic()));
        assertFalse(new SignedRoot("v1", "R", "!!", NOT_AFTER).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot(null, null, newForm().sig(), NOT_AFTER).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot("v1", newForm().root(), newForm().sig(), -1L).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot("v1", newForm().root(), null, NOT_AFTER).verify(POLICY.getPublic()));
    }

    @Test
    void rootSignatureIsNotAKeyringSignature() {
        Map<String, String> services = Map.of("pi", pub(Crypto.generateEd25519KeyPair()));
        SignedRoot root = newForm();
        assertFalse(new KeyringFile(services, pub(POLICY), root.sig(), root.notAfter()).verifies(pub(POLICY)),
                "a root signature offered with a keyring's fields");
        KeyringFile ring = KeyringFile.sign(services, pub(POLICY), NOT_AFTER, POLICY.getPrivate());
        assertFalse(new SignedRoot(root.rootId(), root.root(), ring.sig(), ring.notAfter()).verify(POLICY.getPublic()),
                "a keyring signature offered as a root's");
    }
}
