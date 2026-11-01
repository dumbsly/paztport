// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;

/** v3 over HTTP end to end: a real stamper feeds the encoders, and the real verifier reads what the decoders give. */
class HttpV3Test {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final String RID = "rid-1";
    private static final byte[] BODY = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);

    private final KeyPair gatewayKey = Crypto.generateEd25519KeyPair();
    private final KeyPair ordersKey = Crypto.generateEd25519KeyPair();
    private final KeyPair paymentKey = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment")), 4,
                    NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());

    private StamperV3 stamper(String svc, KeyPair key, boolean origin) {
        return new StamperV3(svc, svc + "-1", key.getPrivate(), origin, () -> RID, () -> NOW);
    }

    private VerifierV3 verifier() {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gatewayKey.getPublic(), "orders", ordersKey.getPublic(),
                        "payment", paymentKey.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), policy.signedRoot().notAfter(),
                Set.of("gateway"), "",
                new InMemoryNonceCache(60_000), () -> NOW, 30_000, 300_000));
    }

    /** gateway to orders to payment, the last stamp bound to POST /pay with BODY. */
    private StamperV3.Stamped sent(List<InfluenceEntry> influence) {
        return sent(influence, RequestBinding.compute("POST", "/pay", BODY));
    }

    private StamperV3.Stamped sent(List<InfluenceEntry> influence, String bind) {
        StamperV3.Stamped first = stamper("gateway", gatewayKey, true).next(List.of(), "orders", "b1", List.of(),
                policy.bundles().get("gateway"));
        return stamper("orders", ordersKey, false).next(first.chain(), "payment",
                bind, influence, policy.bundles().get("orders"));
    }

    @Test
    void requestRoundTrip() {
        List<InfluenceEntry> influence = List.of(
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:example", "h1", null, null));
        StamperV3.Stamped s = sent(influence);
        var in = HttpV3.request(HttpV3.encodeChain(s.chain()), HttpV3.encodeProof(s.proof()),
                HttpV3.encodeInfluence(influence), "POST", "/pay", BODY, "payment", null);
        assertEquals(RID + "|orders|req", in.nonceKey());
        assertEquals(ReasonCode.OK, verifier().verify(in).reason());
    }

    @Test
    void headersAreJcs() {
        String face = "\uD83D\uDE00";
        List<InfluenceEntry> influence = List.of(
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:" + face, "h1", "c", "alice"));
        StamperV3.Stamped s = sent(influence);
        String chain = HttpV3.encodeChain(s.chain());
        String proof = HttpV3.encodeProof(s.proof());
        String infl = HttpV3.encodeInfluence(influence);
        String resp = respondHeader(s, 200, LABELS);
        for (String header : List.of(chain, proof, infl, resp)) {
            JsonReader.token(header);
        }
        assertEquals("[{\"cid\":\"c\",\"cls\":\"third-party\",\"h\":\"h1\",\"owner\":\"alice\",\"src\":\"web:" + face
                + "\"}]", text(infl));
        assertTrue(text(chain).startsWith("[{\"bind\":\"" + s.chain().get(0).bind() + "\",\"infl\":"));
        String p = text(proof);
        assertTrue(p.startsWith("{\"dirs\":\""));
        assertTrue(p.indexOf("\"leafSalt\"") < p.indexOf("\"rootId\""));
        assertTrue(p.indexOf("\"rootId\"") < p.indexOf("\"siblings\""));
        assertTrue(text(resp).startsWith(
                "{\"labels\":[{\"cid\":\"cid-1\",\"cls\":\"private\",\"owner\":\"alice\"}],\"stamp\":{\"bind\":\""));
    }

    private static String text(String header) {
        return new String(Base64Url.decode(header), StandardCharsets.UTF_8);
    }

    @Test
    void noInfluenceIsNoHeader() {
        assertNull(HttpV3.encodeInfluence(List.of()));
        assertEquals("[]", HttpV3.decodeInfluence(null));
    }

    @Test
    void queryIsBound() {
        byte[] none = new byte[0];
        String bindA = RequestBinding.compute("GET", "/search?q=a", none);
        assertNotEquals(bindA, RequestBinding.compute("GET", "/search?q=b", none));
        assertNotEquals(bindA, RequestBinding.compute("GET", "/search", none));
        var asked = HttpV3.request(null, null, null, "GET", "/search?q=a", none, "orders", null);
        assertEquals(bindA, asked.expectedBind());
        assertNotEquals(RequestBinding.compute("GET", "/search", none), asked.expectedBind());

        StamperV3.Stamped s = sent(List.of(), bindA);
        String chain = HttpV3.encodeChain(s.chain());
        String proof = HttpV3.encodeProof(s.proof());
        assertEquals(ReasonCode.OK, verifier().verify(
                HttpV3.request(chain, proof, null, "GET", "/search?q=a", none, "payment", null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpV3.request(chain, proof, null, "GET", "/search?q=b", none, "payment", null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpV3.request(chain, proof, null, "GET", "/search", none, "payment", null)).reason());
    }

    @Test
    void aTargetWithALoneSurrogateIsBindingMismatchAndDoesNotThrow() {
        byte[] none = new byte[0];
        StamperV3.Stamped s = sent(List.of(), RequestBinding.compute("GET", "/search", none));
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpV3.request(HttpV3.encodeChain(s.chain()), HttpV3.encodeProof(s.proof()), null, "GET", "/search\ud800",
                        none, "payment", null)).reason());
    }

    @Test
    void malformedHeaders() {
        StamperV3.Stamped s = sent(List.of());
        String chain = HttpV3.encodeChain(s.chain());
        String proof = HttpV3.encodeProof(s.proof());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(
                HttpV3.request("%%%", proof, null, "POST", "/pay", BODY, "payment", null)).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(
                HttpV3.request(null, proof, null, "POST", "/pay", BODY, "payment", null)).reason());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH, verifier().verify(
                HttpV3.request(chain, proof, "%%%", "POST", "/pay", BODY, "payment", null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(
                HttpV3.request(chain, null, null, "POST", "/pay", BODY, "payment", null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(
                HttpV3.request(chain, "%%%", null, "POST", "/pay", BODY, "payment", null)).reason());
        assertEquals("\"malformed\"", HttpV3.decodeChain("%%%"));
        assertNull(HttpV3.decodeChain(" "));
        assertNull(HttpV3.decodeProof("%%%"));
        assertEquals("", HttpV3.request("%%%", null, null, "GET", "/", BODY, "payment", null).nonceKey());
    }

    private static final List<ContentLabel> LABELS = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-1", "alice"));

    private String respondHeader(StamperV3.Stamped s, int status, List<ContentLabel> labels) {
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(status, BODY), RID,
                labels);
        return HttpV3.encodeResponse(stamp, labels);
    }

    @Test
    void responseCheck() {
        StamperV3.Stamped s = sent(List.of());
        var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), respondHeader(s, 200, LABELS), 200, BODY,
                "orders");
        assertEquals(ReasonCode.OK, check.result().reason());
        assertEquals("payment", check.result().suspectSvc());
        assertEquals(LABELS, check.labels());
        assertEquals(HttpV3.resultHash(200, BODY), check.resultHash());
    }

    @Test
    void responseCheckMissingHeader() {
        StamperV3.Stamped s = sent(List.of());
        var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), null, 200, BODY, "orders");
        assertEquals(ReasonCode.CHAIN_MISSING, check.result().reason());
        assertTrue(check.labels().isEmpty());
        assertEquals(HttpV3.resultHash(200, BODY), check.resultHash());
    }

    @Test
    void responseCheckStatus() {
        StamperV3.Stamped s = sent(List.of());
        var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), respondHeader(s, 200, LABELS), 500, BODY,
                "orders");
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
        assertTrue(check.labels().isEmpty());
    }

    @Test
    void responseCheckLabelsAltered() {
        StamperV3.Stamped s = sent(List.of());
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(200, BODY), RID, LABELS);
        String header = HttpV3.encodeResponse(stamp, List.of(new ContentLabel(InfluenceClass.PUBLIC, "cid-1", null)));
        var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), header, 200, BODY, "orders");
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
        assertTrue(check.labels().isEmpty());
    }

    @Test
    void responseCheckNeverThrows() {
        StamperV3.Stamped s = sent(List.of());
        for (String header : new String[] {"e30", "%%%", "", Base64Url.encode("[]".getBytes(StandardCharsets.UTF_8)),
                Base64Url.encode("{\"stamp\":{},\"labels\":[]}".getBytes(StandardCharsets.UTF_8)),
                Base64Url.encode("{\"stamp\":1,\"labels\":\"x\"}".getBytes(StandardCharsets.UTF_8))}) {
            var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), header, 200, BODY, "orders");
            assertEquals(ReasonCode.CHAIN_MISSING, check.result().reason(), header);
            assertTrue(check.labels().isEmpty());
        }
    }

    @Test
    void responseCheckMalformedLabels() {
        StamperV3.Stamped s = sent(List.of());
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(200, BODY), RID, List.of());
        String header = Base64Url.encode(
                ("{\"labels\":[{\"cid\":\"c\",\"cls\":\"nope\"}],\"stamp\":" + stamp.toJson() + "}")
                        .getBytes(StandardCharsets.UTF_8));
        assertEquals(ReasonCode.CHAIN_MISSING,
                HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), header, 200, BODY, "orders").result().reason());
    }

    /**
     * The response header is read from its bytes: only the JCS bytes of {@code {labels, stamp}} read. A number where
     * a string belongs, a repeated name, or the members in another order is CHAIN_MISSING.
     */
    @Test
    void responseStampIsJudgedAsSent() {
        StamperV3.Stamped s = sent(List.of());
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(200, BODY), RID,
                LABELS);
        String good = stamp.toJson();
        String huge = good.replace("\"svc\":\"payment\"", "\"svc\":1e400");
        String labels = ContentLabel.toJson(LABELS);
        assertEquals(ReasonCode.OK, responseReason(s, "{\"labels\":" + labels + ",\"stamp\":" + good + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"labels\":" + labels + ",\"stamp\":" + huge + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"labels\":" + labels + ",\"stamp\":" + huge + ",\"stamp\":" + good + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"stamp\":" + good + ",\"labels\":" + labels + "}"));
    }

    @Test
    void aResponseHeaderWithAnExtraMemberIsChainMissing() {
        StamperV3.Stamped s = sent(List.of());
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(200, BODY), RID,
                LABELS);
        String labels = ContentLabel.toJson(LABELS);
        assertEquals(ReasonCode.OK, responseReason(s, "{\"labels\":" + labels + ",\"stamp\":" + stamp.toJson() + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"extra\":1,\"labels\":" + labels + ",\"stamp\":" + stamp.toJson() + "}"));
        String extraLabel = "[{\"cid\":\"cid-1\",\"cls\":\"private\",\"extra\":1,\"owner\":\"alice\"}]";
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"labels\":" + extraLabel + ",\"stamp\":" + stamp.toJson() + "}"));
    }

    @Test
    void aResponseHeaderInWireMemberOrderIsChainMissing() {
        StamperV3.Stamped s = sent(List.of());
        StampV3 stamp = stamper("payment", paymentKey, false).respond(s.chain(), HttpV3.resultHash(200, BODY), RID,
                LABELS);
        String wire = "{\"stamp\":" + stamp.toJson() + ",\"labels\":" + ContentLabel.toJson(LABELS) + "}";
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, wire));
        assertEquals(ReasonCode.OK, check(s, HttpV3.encodeResponse(stamp, LABELS)));
    }

    private ReasonCode check(StamperV3.Stamped s, String header) {
        return HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), header, 200, BODY, "orders").result().reason();
    }

    private ReasonCode responseReason(StamperV3.Stamped s, String envelope) {
        String header = Base64Url.encode(envelope.getBytes(StandardCharsets.UTF_8));
        return HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), header, 200, BODY, "orders").result().reason();
    }

    /** A character outside the Basic Multilingual Plane goes in a header as its four UTF-8 bytes. */
    @Test
    void aHeaderHoldsASupplementaryCharacterAsUtf8() {
        InfluenceEntry e = new InfluenceEntry(InfluenceClass.PUBLIC, "s", "\ud83d\ude00", null, null);
        assertEquals("[{\"cls\":\"public\",\"h\":\"\ud83d\ude00\",\"src\":\"s\"}]", Influence.toJson(List.of(e)));
        assertEquals("[{\"cls\":\"public\",\"h\":\"\ud83d\ude00\",\"src\":\"s\"}]",
                new String(Base64Url.decode(HttpV3.encodeInfluence(List.of(e))), StandardCharsets.UTF_8));
    }

    /**
     * A decoder hands on the header's JSON exactly as it was sent, which is the JCS text of what it holds; anything
     * else, spacing, an escape JCS does not write or another member order among it, does not read.
     */
    @Test
    void decodersKeepTheTextAsSent() {
        String text = "[{\"a\":\"A\",\"b\":1}]";
        String header = Base64Url.encode(text.getBytes(StandardCharsets.UTF_8));
        assertEquals(text, HttpV3.decodeChain(header));
        assertEquals(text, HttpV3.decodeInfluence(header));
        assertEquals(text, HttpV3.decodeProof(header));
        for (String unread : new String[] {"[] []", " [{\"a\":\"A\",\"b\":1}] ", "[{\"a\":\"\\u0041\",\"b\":1}]",
                "[{\"b\":1,\"a\":\"A\"}]"}) {
            String h = Base64Url.encode(unread.getBytes(StandardCharsets.UTF_8));
            assertEquals("\"malformed\"", HttpV3.decodeChain(h), unread);
            assertEquals("\"malformed\"", HttpV3.decodeInfluence(h), unread);
            assertNull(HttpV3.decodeProof(h), unread);
        }
    }

    @Test
    void responseCheckRidTheBindingCannotCarry() {
        // A newline in the rid cannot be bound, so a verifier cannot compute the binding and must reject.
        StamperV3.Stamped first = new StamperV3("gateway", "gw-1", gatewayKey.getPrivate(), true, () -> "a\nb", () -> NOW)
                .next(List.of(), "orders", "b1", List.of(), policy.bundles().get("gateway"));
        StamperV3.Stamped s = stamper("orders", ordersKey, false).next(first.chain(), "payment", "b2", List.of(),
                policy.bundles().get("orders"));
        StampV3 stamp = StampV3.sign("payment", "payment-1", "a\nb", NOW, "", "orders", "x", "",
                s.chain().get(1).sig(), paymentKey.getPrivate());
        var check = HttpV3.verifyResponse(verifier(), s.chain(), s.proof(), HttpV3.encodeResponse(stamp, List.of()), 200,
                BODY, "orders");
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
        assertTrue(check.labels().isEmpty());
    }

    @Test
    void responseCheckLoneSurrogateRid() {
        // Unsigned stamps are fine here: the binding is computed before any signature is looked at.
        StampV3 first = new StampV3("gateway", "gw-1", "\uD800", NOW, "", "orders", "b1", "", "", "");
        StampV3 second = new StampV3("orders", "ord-1", "\uD800", NOW, "", "payment", "b2", "", "x", "");
        StampV3 response = StampV3.sign("payment", "payment-1", RID, NOW, "", "orders", "x", "", "y",
                paymentKey.getPrivate());
        var check = HttpV3.verifyResponse(verifier(), List.of(first, second), null,
                HttpV3.encodeResponse(response, List.of()), 200, BODY, "orders");
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
        assertTrue(check.labels().isEmpty());
    }

    @Test
    void resultHashBindsStatusAndBody() {
        assertNotEquals(HttpV3.resultHash(200, BODY), HttpV3.resultHash(201, BODY));
        assertNotEquals(HttpV3.resultHash(200, BODY), HttpV3.resultHash(200, new byte[0]));
        assertEquals(Base64Url.encode(Crypto.sha256("http-response\n200\n".getBytes(StandardCharsets.UTF_8))),
                HttpV3.resultHash(200, new byte[0]));
    }
}
