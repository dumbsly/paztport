// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.verify.ReasonCode;

class ChainsTest {

    private static final KeyPair KEY = Crypto.generateEd25519KeyPair();
    private static final Stamp SIGNED =
            Stamp.sign("pi", "pi-1", "rid-1", 1000, "s", "next", "b", "", "", KEY.getPrivate());

    /** The signed stamp's members, to change before writing them out. */
    private static Map<String, JsonValue> signedStamp() {
        return new LinkedHashMap<>(SIGNED.tree().members());
    }

    /** The JCS text of a chain of these stamps, so each is refused for what it holds, not for its bytes. */
    @SafeVarargs
    private static String chain(Map<String, JsonValue>... stamps) {
        return JsonWriter.text(new JsonValue.Arr(List.of(stamps).stream()
                .map(s -> (JsonValue) new JsonValue.Obj(s)).toList()));
    }

    /** A one-stamp chain's JCS text with the member {@code name}'s value written as {@code text}. */
    private static String chainWith(String name, String text) {
        Map<String, JsonValue> s = signedStamp();
        s.put(name, new JsonValue.Str("@"));
        return chain(s).replace("\"" + name + "\":\"@\"", "\"" + name + "\":" + text);
    }

    private static void rejects(ReasonCode code, String chain) {
        ParsedChain p = Chains.parse(chain);
        assertFalse(p.ok(), chain);
        assertEquals(code, p.failure(), chain);
    }

    @Test
    void notAnArrayOrEmpty() {
        rejects(ReasonCode.CHAIN_MISSING, null);
        rejects(ReasonCode.CHAIN_MISSING, SIGNED.toJson());
        rejects(ReasonCode.CHAIN_MISSING, "\"x\"");
        rejects(ReasonCode.CHAIN_MISSING, "[]");
        rejects(ReasonCode.CHAIN_MISSING, "[7]");
    }

    @Test
    void versionMustBeExactlyThree() {
        Map<String, JsonValue> none = signedStamp();
        none.remove("v");
        rejects(ReasonCode.CHAIN_MISSING, chain(none));
        Map<String, JsonValue> text = signedStamp();
        text.put("v", new JsonValue.Str("3"));
        rejects(ReasonCode.CHAIN_MISSING, chain(text));
        Map<String, JsonValue> four = signedStamp();
        four.put("v", new JsonValue.Int(4));
        rejects(ReasonCode.CHAIN_MISSING, chain(four));
    }

    @Test
    void tsIsAProtocolIntegerByItsText() {
        for (String bad : new String[] {"1.5", "1e3", "9007199254740992", "-1", "-9007199254740991", "\"1\"",
                "null", "1e400",
                // the ends of Java's long: -2^63 has no positive counterpart, so Math.abs of it is negative
                "-9223372036854775808", "9223372036854775807"}) {
            rejects(ReasonCode.CHAIN_MISSING, chainWith("ts", bad));
        }
        Map<String, JsonValue> missing = signedStamp();
        missing.remove("ts");
        rejects(ReasonCode.CHAIN_MISSING, chain(missing));
        for (long ok : new long[] {0, 9007199254740991L}) {
            Map<String, JsonValue> s = signedStamp();
            s.put("ts", new JsonValue.Int(ok));
            ParsedChain p = Chains.parse(chain(s));
            assertTrue(p.ok(), Long.toString(ok));
            assertEquals(ok, p.stamps().get(0).ts());
        }
    }

    @Test
    void aTsOfOnePointZeroIsChainMissing() {
        rejects(ReasonCode.CHAIN_MISSING, chainWith("ts", "1.0"));
        rejects(ReasonCode.CHAIN_MISSING, chainWith("ts", "1000.0"));
    }

    @Test
    void aNegativeTsIsChainMissing() {
        rejects(ReasonCode.CHAIN_MISSING, chainWith("ts", "-1"));
        rejects(ReasonCode.CHAIN_MISSING, chainWith("ts", "-0"));
    }

    @Test
    void stringFieldsMustBeWellFormedStrings() {
        Map<String, JsonValue> num = signedStamp();
        num.put("inst", new JsonValue.Int(7));
        rejects(ReasonCode.CHAIN_MISSING, chain(num));
        rejects(ReasonCode.CHAIN_MISSING, chainWith("inst", "\"\\ud800\""));
        rejects(ReasonCode.CHAIN_MISSING, chainWith("inst", "\"\ud800\""));
        Map<String, JsonValue> nul = signedStamp();
        nul.put("sess", new JsonValue.Null());
        rejects(ReasonCode.CHAIN_MISSING, chain(nul));
    }

    @Test
    void aStampFieldHoldingANoncharacterIsChainMissing() {
        rejects(ReasonCode.CHAIN_MISSING, chainWith("inst", "\"pi-\ufdd0\""));
        rejects(ReasonCode.CHAIN_MISSING, chainWith("rcv", "\"next\uffff\""));
    }

    @Test
    void sigMustBeCanonicalBase64Url() {
        String sig = SIGNED.sig();
        Map<String, JsonValue> padded = signedStamp();
        padded.put("sig", new JsonValue.Str(sig + "="));
        rejects(ReasonCode.CHAIN_MISSING, chain(padded));
        // The decoder reads only the canonical unpadded encoding (RFC 4648 §3.5), so padding and non-zero trailing
        // bits in the last character are refused wherever the text is decoded.
        String canonical = sig.substring(0, sig.length() - 1);
        Map<String, JsonValue> doublePadded = signedStamp();
        doublePadded.put("sig", new JsonValue.Str(canonical + "=="));
        rejects(ReasonCode.CHAIN_MISSING, chain(doublePadded));
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int last = alphabet.indexOf(sig.charAt(sig.length() - 1));
        String tweaked = canonical + alphabet.charAt(last ^ 1);
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode(tweaked));
        Map<String, JsonValue> trailing = signedStamp();
        trailing.put("sig", new JsonValue.Str(tweaked));
        rejects(ReasonCode.CHAIN_MISSING, chain(trailing));
        Map<String, JsonValue> junk = signedStamp();
        junk.put("sig", new JsonValue.Str("!!!"));
        rejects(ReasonCode.CHAIN_MISSING, chain(junk));
        Map<String, JsonValue> absent = signedStamp();
        absent.remove("sig");
        rejects(ReasonCode.CHAIN_MISSING, chain(absent));
    }

    @Test
    void delimiterIsABadSignatureNotAParseError() {
        Map<String, JsonValue> inst = signedStamp();
        inst.put("inst", new JsonValue.Str("a|b"));
        rejects(ReasonCode.BAD_SIGNATURE, chain(inst));
        Map<String, JsonValue> rcv = signedStamp();
        rcv.put("rcv", new JsonValue.Str("x|y"));
        rejects(ReasonCode.BAD_SIGNATURE, chain(rcv));
    }

    @Test
    void structuralFailureOutranksDelimiter() {
        Map<String, JsonValue> bar = signedStamp();
        bar.put("inst", new JsonValue.Str("a|b"));
        Map<String, JsonValue> broken = signedStamp();
        broken.put("ts", new JsonValue.Str("1"));
        rejects(ReasonCode.CHAIN_MISSING, chain(bar, broken));
    }

    @Test
    void aStampNeedsRcv() {
        Map<String, JsonValue> s = signedStamp();
        s.remove("rcv");
        rejects(ReasonCode.CHAIN_MISSING, chain(s));
    }

    @Test
    void aStampWhoseVersionIsNotThreeDoesNotParse() {
        for (int version : new int[] {1, 2, 4}) {
            Map<String, JsonValue> odd = signedStamp();
            odd.put("v", new JsonValue.Int(version));
            rejects(ReasonCode.CHAIN_MISSING, chain(odd));
            rejects(ReasonCode.CHAIN_MISSING, chain(odd, signedStamp()));
            rejects(ReasonCode.CHAIN_MISSING, chain(signedStamp(), odd));
        }
    }

    @Test
    void aStampWithAnExtraMemberIsChainMissing() {
        Map<String, JsonValue> s = signedStamp();
        s.put("extra", new JsonValue.Bool(true));
        rejects(ReasonCode.CHAIN_MISSING, chain(s));
        assertTrue(Chains.parse(chain(signedStamp())).ok());
    }

    @Test
    void aChainInWireMemberOrderIsChainMissing() {
        Stamp s = SIGNED;
        String wireOrder = "[{\"v\":3,\"svc\":\"" + s.svc() + "\",\"inst\":\"" + s.inst() + "\",\"rid\":\"" + s.rid()
                + "\",\"ts\":" + s.ts() + ",\"sess\":\"" + s.sess() + "\",\"rcv\":\"" + s.rcv() + "\",\"bind\":\""
                + s.bind() + "\",\"infl\":\"" + s.infl() + "\",\"prev\":\"" + s.prev() + "\",\"sig\":\"" + s.sig()
                + "\"}]";
        rejects(ReasonCode.CHAIN_MISSING, wireOrder);
        rejects(ReasonCode.CHAIN_MISSING, "[ " + SIGNED.toJson() + " ]");
        assertEquals(List.of(SIGNED), Chains.parse("[" + SIGNED.toJson() + "]").stamps());
    }

    @Test
    void addressedTo() {
        assertTrue(Chains.addressedTo("payment", "payment"));
        assertTrue(Chains.addressedTo("payment#charge", "payment"));
        assertFalse(Chains.addressedTo("payment#", "payment"));
        assertFalse(Chains.addressedTo("paymentx", "payment"));
        assertFalse(Chains.addressedTo("search#find", "payment"));
        assertFalse(Chains.addressedTo("payment", "payment#charge"));
    }

    @Test
    void routeFromRcv() {
        List<Stamp> stamps = List.of(
                Stamp.sign("gateway", "g-1", "rid-1", 1000, "", "orders#createOrder", "b", "", "", KEY.getPrivate()),
                Stamp.sign("orders", "o-1", "rid-1", 1000, "", "payment#charge", "b", "", "x", KEY.getPrivate()));
        assertEquals("gateway/orders#createOrder/payment#charge", Chains.route(stamps, true));
        assertEquals("gateway/orders#createOrder", Chains.route(stamps, false));
    }
}
