// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.paztport.core.session.ReplyCert;

class SignedRootTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final long NOT_AFTER = 1_798_761_600_000L;
    private static final long MAX_SAFE = (1L << 53) - 1;
    private static final byte[] ROOT = Crypto.sha256("root".getBytes(StandardCharsets.UTF_8));

    private static SignedRoot signedRoot() {
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

        SignedRoot signed = SignedRoot.sign(root, "v1", NOT_AFTER, policy.getPrivate());

        assertTrue(signed.verify(policy.getPublic()));
        assertArrayEquals(root, signed.rootBytes());
        assertEquals("v1", signed.rootId());
    }

    @Test
    void verifyFailsWithWrongPolicyKey() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair attacker = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", NOT_AFTER, policy.getPrivate());

        assertFalse(signed.verify(attacker.getPublic()));
    }

    @Test
    void verifyFailsWhenRootTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", NOT_AFTER, policy.getPrivate());

        SignedRoot forged = new SignedRoot(
                signed.rootId(), Base64Url.encode(Crypto.sha256("evil".getBytes())), signed.sig(), signed.notAfter());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void verifyFailsWhenRootIdTampered() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", NOT_AFTER, policy.getPrivate());

        SignedRoot forged = new SignedRoot("v2", signed.root(), signed.sig(), signed.notAfter());
        assertFalse(forged.verify(policy.getPublic()));
    }

    @Test
    void encodeDecodeRoundTrips() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        SignedRoot signed = SignedRoot.sign(Crypto.sha256("root".getBytes()), "v1", NOT_AFTER, policy.getPrivate());

        SignedRoot decoded = SignedRoot.decode(signed.encode());
        assertEquals(signed, decoded);
        assertTrue(decoded.verify(policy.getPublic()));
    }

    @Test
    void signsUnderItsOwnDomainPrefix() {
        assertEquals("paztport-root\n{\"notAfter\":1798761600000,\"root\":\"R\",\"rootId\":\"v1\"}",
                new String(SignedRoot.signingBytes("v1", "R", NOT_AFTER), StandardCharsets.UTF_8));
        assertEquals("paztport-root\n{\"notAfter\":9007199254740991,\"root\":\"R\",\"rootId\":\"v1\"}",
                new String(SignedRoot.signingBytes("v1", "R", MAX_SAFE), StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.signingBytes("v1", "R", -1));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.signingBytes("v1", "R", MAX_SAFE + 1));
    }

    @Test
    void roundTrip() throws Exception {
        SignedRoot r = signedRoot();
        assertEquals(NOT_AFTER, r.notAfter());
        assertEquals("v1", r.rootId());
        assertArrayEquals(ROOT, r.rootBytes());
        assertTrue(r.verify(POLICY.getPublic()));
        assertFalse(r.verify(Crypto.generateEd25519KeyPair().getPublic()));

        SignedRoot parsed = SignedRoot.parse(r.toJson());
        assertEquals(r, parsed);
        assertTrue(parsed.verify(POLICY.getPublic()));
        assertEquals(r, SignedRoot.decode(r.encode()));
        // The readers that still bind the record keep the window.
        assertEquals(r, JSON.readValue(JSON.writeValueAsBytes(r), SignedRoot.class));
    }

    @Test
    void tamperedNotAfterFails() {
        SignedRoot r = signedRoot();
        assertFalse(new SignedRoot(r.rootId(), r.root(), r.sig(), NOT_AFTER + 1).verify(POLICY.getPublic()));
    }

    @Test
    void aSignatureOverRootIdAndRootAloneFails() {
        String sig = Base64Url.encode(Crypto.sign(POLICY.getPrivate(),
                ("v1|" + Base64Url.encode(ROOT)).getBytes(StandardCharsets.UTF_8)));
        assertFalse(new SignedRoot("v1", Base64Url.encode(ROOT), sig, NOT_AFTER).verify(POLICY.getPublic()),
                "a window must not be lent to a signature that never covered one");
    }

    @Test
    void tamperedRootOrRootIdFails() {
        SignedRoot r = signedRoot();
        assertFalse(new SignedRoot("v2", r.root(), r.sig(), r.notAfter()).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot(r.rootId(), Base64Url.encode(Crypto.sha256("evil".getBytes())), r.sig(),
                r.notAfter()).verify(POLICY.getPublic()));
    }

    @Test
    void currentAtNotAfterNotAfter() {
        SignedRoot r = signedRoot();
        assertTrue(r.isCurrent(NOT_AFTER - 1));
        assertTrue(r.isCurrent(NOT_AFTER));
        assertFalse(r.isCurrent(NOT_AFTER + 1));
    }

    @Test
    void renewedKeepsRootAndRootId() {
        SignedRoot old = SignedRoot.sign(ROOT, "v1", 1000, POLICY.getPrivate());
        SignedRoot renewed = old.renewed(NOT_AFTER + 5, POLICY.getPrivate());
        assertEquals(old.rootId(), renewed.rootId());
        assertEquals(old.root(), renewed.root());
        assertEquals(NOT_AFTER + 5, renewed.notAfter());
        assertTrue(renewed.verify(POLICY.getPublic()));
        SignedRoot again = signedRoot().renewed(NOT_AFTER + 9, POLICY.getPrivate());
        assertEquals(NOT_AFTER + 9, again.notAfter());
        assertTrue(again.verify(POLICY.getPublic()));
    }

    @Test
    void notAfterIsAProtocolInteger() throws Exception {
        SignedRoot r = signedRoot();
        String head = "{\"rootId\":\"v1\",\"root\":\"" + r.root() + "\",\"sig\":\"" + r.sig() + "\",\"notAfter\":";
        assertEquals(MAX_SAFE, SignedRoot.parse(head + MAX_SAFE + "}").notAfter());
        assertEquals(0L, SignedRoot.parse(head + "0}").notAfter());
        assertTrue(SignedRoot.parse(head + NOT_AFTER + "}").verify(POLICY.getPublic()));
        for (String bad : new String[] {"1.0e12", "1798761600000.0", "1.5", "-1", String.valueOf(MAX_SAFE + 1),
                "\"1798761600000\"", "null", "true", "{}", "[]"}) {
            assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(head + bad + "}"), bad);
        }
    }

    @Test
    void parseRefusesAMalformedRoot() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(null));
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse("[]"));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse("{\"root\":\"R\",\"sig\":\"S\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse("{\"rootId\":1,\"root\":\"R\",\"sig\":\"S\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.parse("{\"rootId\":\"v1\",\"root\":\"R\"}"));
    }

    @Test
    void loadReadsTheFileStrictly(@TempDir Path dir) throws Exception {
        SignedRoot r = signedRoot();
        Path file = dir.resolve("root.json");
        Files.write(file, JSON.writeValueAsBytes(r));
        assertEquals(r, SignedRoot.load(file));
        Files.writeString(file, "{\"rootId\":\"v1\",\"root\":\"R\",\"sig\":\"S\",\"notAfter\":1.5}");
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file));
        Files.writeString(file, "{not json");
        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file));
    }

    /**
     * A root without {@code notAfter} is malformed, read from text, from a file or from its encoding, with the answer
     * a {@code notAfter} that is not an integer gets. Its signature is over {@code rootId|root}, so it would verify
     * were the reader to take the missing window for none.
     */
    @Test
    void aRootWithoutNotAfterIsRefused(@TempDir Path dir) throws Exception {
        String root = Base64Url.encode(ROOT);
        String sig = Base64Url.encode(Crypto.sign(POLICY.getPrivate(),
                ("v1|" + root).getBytes(StandardCharsets.UTF_8)));
        String text = "{\"root\":\"" + root + "\",\"rootId\":\"v1\",\"sig\":\"" + sig + "\"}";
        String message = "no member notAfter";
        assertEquals(message, assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(text)).getMessage());
        assertEquals(message, assertThrows(IllegalArgumentException.class,
                () -> SignedRoot.decode(Base64Url.encode(text.getBytes(StandardCharsets.UTF_8)))).getMessage());
        Path file = dir.resolve("root.json");
        Files.writeString(file, text);
        assertEquals(message, assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file)).getMessage());
    }

    /**
     * A file is read in any member order and spacing: here as Jackson's pretty printer writes one, members in the
     * record's order, {@code " : "} between a name and its value, and no newline at the end.
     */
    @Test
    void aFileInAnyMemberOrderAndSpacingLoads(@TempDir Path dir) throws Exception {
        SignedRoot r = signedRoot();
        String text = "{\n  \"rootId\" : \"v1\",\n  \"root\" : \"" + r.root() + "\",\n  \"sig\" : \"" + r.sig()
                + "\",\n  \"notAfter\" : " + NOT_AFTER + "\n}";
        Path file = dir.resolve("root.json");
        Files.writeString(file, text);
        assertEquals(r, SignedRoot.load(file));
        assertEquals(r, SignedRoot.parse(text));
    }

    /** A {@code notAfter} is a protocol integer by its text: {@code 1798761600000.0} does not read, though equal. */
    @Test
    void aNotAfterWrittenWithAFractionIsMalformed(@TempDir Path dir) throws Exception {
        String text = signedRoot().toFile().replace(NOT_AFTER + ",", NOT_AFTER + ".0,");
        assertTrue(text.contains("1798761600000.0"), text);
        Path file = dir.resolve("root.json");
        Files.writeString(file, text);
        assertEquals(Step.PARSE, assertThrows(MalformedJsonException.class, () -> SignedRoot.load(file)).step());
        assertEquals(Step.PARSE, assertThrows(MalformedJsonException.class, () -> SignedRoot.parse(text)).step());
    }

    /** A member the root does not define is refused, not ignored. */
    @Test
    void anExtraMemberIsMalformed(@TempDir Path dir) throws Exception {
        String text = signedRoot().toFile().replace("{\n", "{\n  \"note\": \"not signed\",\n");
        Path file = dir.resolve("root.json");
        Files.writeString(file, text);
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(file)).getMessage());
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> SignedRoot.parse(text)).getMessage());
    }

    /** A token is a wire object: the root's JCS bytes and no other spelling of them. */
    @Test
    void aTokenThatIsNotTheRootsCanonicalBytesIsMalformed() {
        SignedRoot r = signedRoot();
        assertEquals(r, SignedRoot.decode(r.encode()));
        String spaced = Base64Url.encode(r.toFile().getBytes(StandardCharsets.UTF_8));
        assertEquals(Step.CANONICAL,
                assertThrows(MalformedJsonException.class, () -> SignedRoot.decode(spaced)).step());
    }

    @Test
    void verifyNeverThrows() {
        assertFalse(new SignedRoot("v1", "R", "!!", NOT_AFTER).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot(null, null, signedRoot().sig(), NOT_AFTER).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot("v1", signedRoot().root(), signedRoot().sig(), -1L).verify(POLICY.getPublic()));
        assertFalse(new SignedRoot("v1", signedRoot().root(), null, NOT_AFTER).verify(POLICY.getPublic()));
    }

    @Test
    void rootSignatureIsNotAKeyringSignature() {
        Map<String, String> services = Map.of("pi", pub(Crypto.generateEd25519KeyPair()));
        SignedRoot root = signedRoot();
        assertFalse(new KeyringFile(services, pub(POLICY), root.sig(), root.notAfter()).verifies(pub(POLICY)),
                "a root signature offered with a keyring's fields");
        KeyringFile ring = KeyringFile.sign(services, pub(POLICY), NOT_AFTER, POLICY.getPrivate());
        assertFalse(new SignedRoot(root.rootId(), root.root(), ring.sig(), ring.notAfter()).verify(POLICY.getPublic()),
                "a keyring signature offered as a root's");
    }

    // These would also fail incidentally, since the bodies differ; the literal signing-bytes tests are what pin the
    // prefixes.
    @Test
    void rootSignatureIsNotAReplyCertificateSignature() {
        SignedRoot root = signedRoot();
        ReplyCert cert = ReplyCert.issue(pub(POLICY), "partner", pub(Crypto.generateEd25519KeyPair()), NOT_AFTER,
                POLICY.getPrivate());
        assertTrue(root.verify(POLICY.getPublic()) && cert.verifies(pub(POLICY)));
        assertFalse(new SignedRoot(root.rootId(), root.root(), cert.sig(), cert.notAfter()).verify(POLICY.getPublic()),
                "a reply-certificate signature offered as a root's");
        assertFalse(new ReplyCert(cert.policy(), cert.svc(), cert.key(), cert.notAfter(), root.sig())
                .verifies(pub(POLICY)), "a root signature offered as a reply certificate's");
    }
}
