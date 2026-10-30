// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.verify.ReasonCode;

class ChainsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final KeyPair KEY = Crypto.generateEd25519KeyPair();

    private static ObjectNode v3() {
        return StampV3.sign("pi", "pi-1", "rid-1", 1000, "s", "next", "b", "", "", KEY.getPrivate()).tree();
    }

    private static ObjectNode v2() {
        ObjectNode o = v3();
        o.put("v", 2);
        o.remove("rcv");
        return o;
    }

    private static ArrayNode chain(JsonNode... stamps) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        for (JsonNode s : stamps) {
            a.add(s);
        }
        return a;
    }

    private static void rejects(ReasonCode code, JsonNode chain) {
        ParsedChain p = Chains.parse(chain == null ? null : chain.toString(), true);
        assertFalse(p.ok());
        assertEquals(code, p.failure());
    }

    @Test
    void notAnArrayOrEmpty() throws Exception {
        rejects(ReasonCode.CHAIN_MISSING, null);
        rejects(ReasonCode.CHAIN_MISSING, v3());
        rejects(ReasonCode.CHAIN_MISSING, MAPPER.readTree("\"x\""));
        rejects(ReasonCode.CHAIN_MISSING, chain());
        rejects(ReasonCode.CHAIN_MISSING, chain(MAPPER.readTree("7")));
    }

    @Test
    void versionMustBeExactlyTwoOrThree() {
        ObjectNode none = v3();
        none.remove("v");
        rejects(ReasonCode.CHAIN_MISSING, chain(none));
        ObjectNode text = v3();
        text.put("v", "3");
        rejects(ReasonCode.CHAIN_MISSING, chain(text));
        ObjectNode four = v3();
        four.put("v", 4);
        rejects(ReasonCode.CHAIN_MISSING, chain(four));
    }

    @Test
    void tsIsCheckedByValue() throws Exception {
        for (String bad : new String[] {"1.5", "9007199254740992", "-9007199254740992", "\"1\"", "null", "1e400"}) {
            ObjectNode s = v3();
            s.set("ts", MAPPER.readTree(bad));
            rejects(ReasonCode.CHAIN_MISSING, chain(s));
        }
        ObjectNode missing = v3();
        missing.remove("ts");
        rejects(ReasonCode.CHAIN_MISSING, chain(missing));
        for (String ok : new String[] {"1.0", "1e3", "9007199254740991"}) {
            ObjectNode s = v3();
            s.set("ts", MAPPER.readTree(ok));
            assertTrue(Chains.parse(chain(s).toString(), false).ok(), ok);
        }
        ObjectNode one = v3();
        one.set("ts", MAPPER.readTree("1.0"));
        assertEquals(1L, Chains.parse(chain(one).toString(), false).stamps().get(0).ts());
    }

    @Test
    void stringFieldsMustBeWellFormedStrings() {
        ObjectNode num = v3();
        num.put("inst", 7);
        rejects(ReasonCode.CHAIN_MISSING, chain(num));
        ObjectNode lone = v3();
        lone.put("inst", "\ud800");
        rejects(ReasonCode.CHAIN_MISSING, chain(lone));
        ObjectNode nul = v3();
        nul.putNull("sess");
        rejects(ReasonCode.CHAIN_MISSING, chain(nul));
    }

    @Test
    void sigMustBeCanonicalBase64Url() {
        ObjectNode padded = v3();
        padded.put("sig", padded.get("sig").asText() + "=");
        rejects(ReasonCode.CHAIN_MISSING, chain(padded));
        // Java's decoder accepts "==" padding on a 64-byte signature, and non-zero trailing bits in the last
        // character; both decode to the same bytes, so only the re-encode comparison refuses them.
        String canonical = padded.get("sig").asText().substring(0, padded.get("sig").asText().length() - 1);
        ObjectNode doublePadded = v3();
        doublePadded.put("sig", canonical + "==");
        assertEquals(Base64Url.decode(canonical).length, Base64Url.decode(canonical + "==").length);
        rejects(ReasonCode.CHAIN_MISSING, chain(doublePadded));
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int last = alphabet.indexOf(canonical.charAt(canonical.length() - 1));
        char twin = alphabet.charAt(last ^ 1);
        String tweaked = canonical.substring(0, canonical.length() - 1) + twin;
        assertTrue(java.util.Arrays.equals(Base64Url.decode(canonical), Base64Url.decode(tweaked)));
        ObjectNode trailing = v3();
        trailing.put("sig", tweaked);
        rejects(ReasonCode.CHAIN_MISSING, chain(trailing));
        ObjectNode junk = v3();
        junk.put("sig", "!!!");
        rejects(ReasonCode.CHAIN_MISSING, chain(junk));
        ObjectNode absent = v3();
        absent.remove("sig");
        rejects(ReasonCode.CHAIN_MISSING, chain(absent));
    }

    @Test
    void delimiterIsABadSignatureNotAParseError() {
        ObjectNode inst = v3();
        inst.put("inst", "a|b");
        rejects(ReasonCode.BAD_SIGNATURE, chain(inst));
        ObjectNode rcv = v3();
        rcv.put("rcv", "x|y");
        rejects(ReasonCode.BAD_SIGNATURE, chain(rcv));
    }

    @Test
    void structuralFailureOutranksDelimiter() {
        ObjectNode bar = v3();
        bar.put("inst", "a|b");
        ObjectNode broken = v3();
        broken.put("ts", "1");
        rejects(ReasonCode.CHAIN_MISSING, chain(bar, broken));
    }

    @Test
    void v3NeedsRcv() {
        ObjectNode s = v3();
        s.remove("rcv");
        rejects(ReasonCode.CHAIN_MISSING, chain(s));
    }

    @Test
    void legacyV2OnlyWhenAccepted() {
        assertEquals(ReasonCode.CHAIN_MISSING, Chains.parse(chain(v2()).toString(), false).failure());
        ParsedChain p = Chains.parse(chain(v2(), v2()).toString(), true);
        assertTrue(p.ok());
        assertTrue(p.legacy());
        assertNull(p.failure());
        assertNull(p.stamps().get(0).rcvOrNull());
        assertFalse(Chains.parse(chain(v3()).toString(), true).legacy());
    }

    @Test
    void strayRcvOnV2IsIgnored() {
        ObjectNode s = v2();
        s.put("rcv", 9);
        ParsedChain p = Chains.parse(chain(s).toString(), true);
        assertTrue(p.ok());
        assertNull(p.stamps().get(0).rcvOrNull());
    }

    @Test
    void mixedVersionsDoNotParse() {
        rejects(ReasonCode.CHAIN_MISSING, chain(v2(), v3()));
        rejects(ReasonCode.CHAIN_MISSING, chain(v3(), v2()));
    }

    @Test
    void unknownFieldsAreIgnored() {
        ObjectNode s = v3();
        s.put("extra", true);
        assertTrue(Chains.parse(chain(s).toString(), false).ok());
    }
}
