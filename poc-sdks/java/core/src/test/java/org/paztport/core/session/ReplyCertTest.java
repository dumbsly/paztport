// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class ReplyCertTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair OTHER = Crypto.generateEd25519KeyPair();
    private static final KeyPair ENTRY = Crypto.generateEd25519KeyPair();
    private static final long NOT_AFTER = 1_798_761_600_000L;
    private static final long MAX_SAFE = (1L << 53) - 1;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static ReplyCert issued() {
        return ReplyCert.issue(pub(POLICY), "mcp-entry", pub(ENTRY), NOT_AFTER, POLICY.getPrivate());
    }

    private static JsonNode json(String text) throws Exception {
        return JSON.readTree(text);
    }

    @Test
    void signsTheFourFieldsUnderADomainPrefix() {
        assertEquals("paztport-reply-cert\n{\"key\":\"K\",\"notAfter\":1798761600000,\"policy\":\"P\",\"svc\":\"s\"}",
                new String(ReplyCert.signingBytes("P", "s", "K", NOT_AFTER), StandardCharsets.UTF_8));
        assertEquals(
                "paztport-reply-cert\n{\"key\":\"K\",\"notAfter\":9007199254740991,\"policy\":\"P\",\"svc\":\"s\"}",
                new String(ReplyCert.signingBytes("P", "s", "K", MAX_SAFE), StandardCharsets.UTF_8));
    }

    @Test
    void issuedVerifiesUnderItsPolicyKey() {
        ReplyCert c = issued();
        assertEquals(pub(POLICY), c.policy());
        assertEquals("mcp-entry", c.svc());
        assertEquals(pub(ENTRY), c.key());
        assertEquals(NOT_AFTER, c.notAfter());
        assertTrue(c.verifies(pub(POLICY)));
    }

    @Test
    void tamperedNotAfterFails() {
        ReplyCert c = issued();
        assertFalse(new ReplyCert(c.policy(), c.svc(), c.key(), c.notAfter() + 1, c.sig()).verifies(pub(POLICY)));
    }

    @Test
    void tamperedSvcFails() {
        ReplyCert c = issued();
        assertFalse(new ReplyCert(c.policy(), "github-tools", c.key(), c.notAfter(), c.sig()).verifies(pub(POLICY)));
    }

    @Test
    void tamperedKeyFails() {
        ReplyCert c = issued();
        assertFalse(new ReplyCert(c.policy(), c.svc(), pub(OTHER), c.notAfter(), c.sig()).verifies(pub(POLICY)));
    }

    @Test
    void signedByAnotherPolicyKeyFails() {
        // Names the pinned policy key, but the signature is another key's.
        ReplyCert forged = ReplyCert.issue(pub(POLICY), "mcp-entry", pub(ENTRY), NOT_AFTER, OTHER.getPrivate());
        assertFalse(forged.verifies(pub(POLICY)));
    }

    @Test
    void policyNotThePinFails() {
        // A sound certificate from another policy key: it verifies under its own key, never under the pin.
        ReplyCert other = ReplyCert.issue(pub(OTHER), "mcp-entry", pub(ENTRY), NOT_AFTER, OTHER.getPrivate());
        assertTrue(other.verifies(pub(OTHER)));
        assertFalse(other.verifies(pub(POLICY)));
    }

    @Test
    void malformedFieldsNeverThrow() {
        ReplyCert c = issued();
        assertFalse(new ReplyCert(c.policy(), c.svc(), c.key(), c.notAfter(), "!!").verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), c.svc(), c.key(), c.notAfter(), null).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(null, c.svc(), c.key(), c.notAfter(), c.sig()).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), null, c.key(), c.notAfter(), c.sig()).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), c.svc(), null, c.notAfter(), c.sig()).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), c.svc(), c.key(), -1, c.sig()).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), c.svc(), c.key(), MAX_SAFE + 1, c.sig()).verifies(pub(POLICY)));
        assertFalse(new ReplyCert(c.policy(), "x\ud800", c.key(), c.notAfter(), c.sig()).verifies(pub(POLICY)));
        assertFalse(c.verifies(null));
        assertFalse(c.verifies("!!"));
    }

    @Test
    void issueRefusesAnOutOfRangeNotAfter() {
        assertThrows(IllegalArgumentException.class,
                () -> ReplyCert.issue(pub(POLICY), "mcp-entry", pub(ENTRY), -1, POLICY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> ReplyCert.issue(pub(POLICY), "mcp-entry", pub(ENTRY), MAX_SAFE + 1, POLICY.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> ReplyCert.signingBytes("P", "s", "K", -1));
    }

    private static ObjectNode tree(ReplyCert c) {
        try {
            return (ObjectNode) JSON.readTree(c.toJson());
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void jsonRoundTrips() throws Exception {
        ReplyCert c = issued();
        ObjectNode o = tree(c);
        List<String> names = new ArrayList<>();
        o.fieldNames().forEachRemaining(names::add);
        assertEquals(List.of("key", "notAfter", "policy", "sig", "svc"), names);
        assertTrue(o.get("notAfter").isIntegralNumber());
        assertEquals(c, ReplyCert.parse(JSON.writeValueAsString(o)));
    }

    /** A member the certificate does not define is refused, not ignored, read from text or from its file. */
    @Test
    void anExtraMemberIsMalformed(@TempDir Path dir) throws Exception {
        String text = issued().toFile().replace("{\n", "{\n  \"note\": \"not signed\",\n");
        Path file = dir.resolve("reply-cert.json");
        Files.writeString(file, text);
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> ReplyCert.load(file)).getMessage());
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(text)).getMessage());
    }

    @Test
    void parseRefusesANotAfterThatIsNotAProtocolInteger() throws Exception {
        // A protocol integer by its text: an integer written with a fraction or an exponent is refused too.
        for (String bad : new String[] {"1.0", "1e3", "1798761600000.0", "1.7987616E12", "1.5", "-1", "-1.0",
                "9007199254740992", "9.007199254740992e15", "18446744073709551616", "\"1798761600000\"", "\"1e3\"",
                "null", "true", "[]", "{}"}) {
            ObjectNode o = tree(issued());
            o.set("notAfter", json(bad));
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(o.toString()), bad);
        }
    }

    @Test
    void parseAcceptsTheRangeEnds() throws Exception {
        for (long ok : new long[] {0, MAX_SAFE}) {
            ObjectNode o = tree(issued());
            o.put("notAfter", ok);
            assertEquals(ok, ReplyCert.parse(o.toString()).notAfter());
        }
    }

    @Test
    void parseRefusesAMissingOrNonStringField() {
        for (String field : new String[] {"policy", "svc", "key", "notAfter", "sig"}) {
            ObjectNode missing = tree(issued());
            missing.remove(field);
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(missing.toString()), field);
        }
        for (String field : new String[] {"policy", "svc", "key", "sig"}) {
            ObjectNode number = tree(issued());
            number.put(field, 1);
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(number.toString()), field);
            ObjectNode nul = tree(issued());
            nul.putNull(field);
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(nul.toString()), field);
        }
    }

    @Test
    void parseRefusesANonObject() throws Exception {
        for (String bad : new String[] {"null", "[]", "\"cert\"", "1"}) {
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> ReplyCert.parse(null));
    }

    @Test
    void loadsTheToolsFile(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("reply-cert.json");
        Files.writeString(f, tree(issued()).toPrettyString());
        assertEquals(issued(), ReplyCert.load(f));
        for (String bad : new String[] {"{not json", "", "[]", issued().toJson() + " {}"}) {
            Files.writeString(f, bad);
            assertThrows(IllegalArgumentException.class, () -> ReplyCert.load(f), bad);
        }
    }
}
