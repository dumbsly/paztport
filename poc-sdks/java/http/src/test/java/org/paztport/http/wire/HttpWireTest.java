// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
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
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyResult;

/**
 * Version 4 over HTTP end to end: a real stamper feeds the encoders, and the real verifier reads what the decoders
 * give.
 */
class HttpWireTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final String RID = "rid-1";
    private static final byte[] BODY = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
    private static final ExtensionSettings INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null,
            null);
    /** Orders' block: it acts on influence and has added one entry of its own. */
    private static final Block ORDERS_BLOCK = Influence.block(List.of(WEB), List.of());
    private static final List<ContentLabel> LABELS =
            List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-1", "alice"));
    /** Payment's response block: it acts on influence and labels its answer. */
    private static final Block LABELLED = ContentLabel.block(LABELS, List.of());

    private final KeyPair gatewayKey = Crypto.generateEd25519KeyPair();
    private final KeyPair ordersKey = Crypto.generateEd25519KeyPair();
    private final KeyPair paymentKey = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment")), 4,
                    NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());
    private final PolicyBuilder.Result ops = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment#charge")), 4,
                    NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());

    private Stamper stamper(String svc, KeyPair key, boolean origin) {
        return new Stamper(svc, svc + "-1", key.getPrivate(), origin, () -> RID, () -> NOW);
    }

    private Verifier verifier(ExtensionSettings settings) {
        return verifier(policy, new InMemoryNonceCache(60_000), settings);
    }

    private Verifier verifier() {
        return verifier(ExtensionSettings.NONE);
    }

    private Verifier verifier(PolicyBuilder.Result p, NonceCache nonces, ExtensionSettings settings) {
        long notAfter = p.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gatewayKey.getPublic(), "orders",
                        ordersKey.getPublic(), "payment", paymentKey.getPublic())), notAfter)),
                List.of(new PinnedRoot(p.signedRoot().rootBytes(), p.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "", nonces, () -> NOW, 30_000, 300_000, settings));
    }

    /** gateway to orders to payment, the last stamp bound to POST /pay with BODY and committing to ordersBlock. */
    private Stamper.Stamped sent(Block ordersBlock) {
        return sent(ordersBlock, RequestBinding.compute("POST", "/pay", BODY));
    }

    private Stamper.Stamped sent(Block ordersBlock, String bind) {
        return sent(policy, "payment", ordersBlock, bind);
    }

    private Stamper.Stamped sent(PolicyBuilder.Result p, String receiver, Block ordersBlock, String bind) {
        Stamper.Stamped first = stamper("gateway", gatewayKey, true).next(List.of(), "orders", "b1", Block.EMPTY,
                p.bundles().get("gateway"));
        return stamper("orders", ordersKey, false).next(first.chain(), receiver, bind, ordersBlock,
                p.bundles().get("orders"));
    }

    private static String token(String text) {
        return Base64Url.encode(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(String header) {
        return new String(Base64Url.decode(header), StandardCharsets.UTF_8);
    }

    // --- The blocks header ---

    @Test
    void blocksTravelAsATokenAndReadBack() {
        Stamper.Stamped s = sent(ORDERS_BLOCK);
        List<Block> blocks = List.of(Block.EMPTY, ORDERS_BLOCK);

        String header = HttpWire.encodeBlocks(blocks);

        assertEquals(blocks, Block.parseAll(HttpWire.decodeBlocks(header)));
        VerifyResult result = verifier(INFLUENCE).verify(HttpWire.request(HttpWire.encodeChain(s.chain()),
                HttpWire.encodeProof(s.proof()), header, "POST", "/pay", BODY, "payment", null, null));
        assertEquals(ReasonCode.OK, result.reason());
        assertEquals(List.of(new HandOver.StampItems("gateway", null),
                new HandOver.StampItems("orders", List.of(WEB.toJson()))), result.handOver().under(Influence.NAME));
    }

    @Test
    void anAbsentBlocksHeaderIsNoToken() {
        assertNull(HttpWire.decodeBlocks(null));
        assertNull(HttpWire.decodeBlocks(" "));
        // No token is one empty block per stamp, so a chain whose every ext is empty verifies without one.
        Stamper.Stamped s = sent(Block.EMPTY);
        assertEquals(ReasonCode.OK, verifier().verify(HttpWire.request(HttpWire.encodeChain(s.chain()),
                HttpWire.encodeProof(s.proof()), null, "POST", "/pay", BODY, "payment", null, null)).reason());
    }

    /**
     * A header that is present but does not decode is left to check 9a, never taken for an absent
     * one, which on this chain (every ext empty) would verify.
     */
    @Test
    void aBlocksHeaderThatDoesNotDecodeIsNotNull() {
        Stamper.Stamped s = sent(Block.EMPTY);
        for (String header : List.of("!!", token("null"))) {
            assertNotNull(HttpWire.decodeBlocks(header), header);
            assertEquals(ReasonCode.EXTENSION_MISMATCH, verifier().verify(HttpWire.request(
                    HttpWire.encodeChain(s.chain()), HttpWire.encodeProof(s.proof()), header, "POST", "/pay", BODY,
                    "payment", null, null)).reason(), header);
        }
    }

    @Test
    void theRequestNonceKeyIsAJcsArray() {
        Stamper.Stamped s = sent(ops, "payment#charge", Block.EMPTY, "b2");
        String chain = HttpWire.encodeChain(s.chain());

        assertEquals("[\"rid-1\",\"orders\",\"payment#charge\",\"req\"]",
                HttpWire.request(chain, null, null, "POST", "/pay", BODY, "payment#charge", null, null).nonceKey());
        assertEquals("[\"rid-1\",\"orders\",\"payment#charge\",\"A1\",\"req\"]",
                HttpWire.request(chain, null, null, "POST", "/pay", BODY, "payment#charge", "A1", null).nonceKey());
    }

    @Test
    void theResponseNonceKeyIsAJcsArray() {
        List<String> spent = new ArrayList<>();
        Verifier recording = verifier(ops, recording(spent), ExtensionSettings.NONE);
        Stamper.Stamped s = sent(ops, "payment#charge", Block.EMPTY, "b2");
        List<Block> sentBlocks = List.of(Block.EMPTY, Block.EMPTY);

        HttpWire.ResponseCheck bare = HttpWire.verifyResponse(recording, s.chain(), sentBlocks, s.proof(),
                respondHeader(s, 200, Block.EMPTY), 200, BODY, "orders", null);
        HttpWire.ResponseCheck keyed = HttpWire.verifyResponse(recording, s.chain(), sentBlocks, s.proof(),
                respondHeader(s, 200, Block.EMPTY), 200, BODY, "orders", "A1");

        assertEquals(ReasonCode.OK, bare.result().reason());
        assertEquals(ReasonCode.OK, keyed.result().reason());
        assertEquals(List.of("[\"rid-1\",\"payment#charge\",\"resp\"]",
                "[\"rid-1\",\"payment#charge\",\"A1\",\"resp\"]"), spent);
    }

    private static NonceCache recording(List<String> spent) {
        InMemoryNonceCache inner = new InMemoryNonceCache(60_000);
        return new NonceCache() {
            @Override
            public boolean seenBefore(String key, long now) {
                spent.add(key);
                return inner.seenBefore(key, now);
            }

            @Override
            public long ttlMs() {
                return inner.ttlMs();
            }
        };
    }

    @Test
    void headersAreJcs() {
        String face = "\uD83D\uDE00";
        Block faced = Influence.block(List.of(new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:" + face, "h1", "c",
                "alice")), List.of());
        Stamper.Stamped s = sent(faced);
        String chain = HttpWire.encodeChain(s.chain());
        String proof = HttpWire.encodeProof(s.proof());
        String blocks = HttpWire.encodeBlocks(List.of(Block.EMPTY, faced));
        String resp = respondHeader(s, 200, LABELLED);
        for (String header : List.of(chain, proof, blocks, resp)) {
            JsonReader.token(header);
        }
        assertEquals("[{\"items\":{},\"requires\":[]},{\"items\":{\"influence\":[{\"cid\":\"c\","
                + "\"cls\":\"third-party\",\"h\":\"h1\",\"owner\":\"alice\",\"src\":\"web:" + face + "\"}]},"
                + "\"requires\":[]}]", text(blocks));
        assertTrue(text(chain).startsWith("[{\"bind\":\"" + s.chain().get(0).bind() + "\",\"ext\":\"\","));
        String p = text(proof);
        assertTrue(p.startsWith("{\"dirs\":\""));
        assertTrue(p.indexOf("\"leafSalt\"") < p.indexOf("\"rootId\""));
        assertTrue(p.indexOf("\"rootId\"") < p.indexOf("\"siblings\""));
        assertTrue(text(resp).startsWith("{\"block\":{\"items\":{\"influence\":[{\"cid\":\"cid-1\",\"cls\":\"private\","
                + "\"owner\":\"alice\"}]},\"requires\":[\"influence\"]},\"stamp\":{\"bind\":\""));
    }

    /** A character outside the Basic Multilingual Plane goes in a header as its four UTF-8 bytes. */
    @Test
    void aHeaderHoldsASupplementaryCharacterAsUtf8() {
        Block b = Influence.block(List.of(new InfluenceEntry(InfluenceClass.PUBLIC, "s", "\ud83d\ude00", null, null)),
                List.of());
        assertEquals("[{\"items\":{\"influence\":[{\"cls\":\"public\",\"h\":\"\ud83d\ude00\",\"src\":\"s\"}]},"
                + "\"requires\":[]}]", text(HttpWire.encodeBlocks(List.of(b))));
    }

    /**
     * A decoder hands on the header's JSON exactly as it was sent, which is the JCS text of what it holds; anything
     * else, spacing, an escape JCS does not write or another member order among it, does not read.
     */
    @Test
    void decodersKeepTheTextAsSent() {
        String text = "[{\"a\":\"A\",\"b\":1}]";
        String header = token(text);
        assertEquals(text, HttpWire.decodeChain(header));
        assertEquals(text, HttpWire.decodeBlocks(header));
        assertEquals(text, HttpWire.decodeProof(header));
        for (String unread : new String[] {"[] []", " [{\"a\":\"A\",\"b\":1}] ", "[{\"a\":\"\\u0041\",\"b\":1}]",
                "[{\"b\":1,\"a\":\"A\"}]"}) {
            String h = token(unread);
            assertEquals("\"malformed\"", HttpWire.decodeChain(h), unread);
            String blocks = HttpWire.decodeBlocks(h);
            assertNotNull(blocks, unread);
            assertTrue(isUnreadable(blocks), "blocks that do not decode do not read as JSON: " + unread);
            assertNull(HttpWire.decodeProof(h), unread);
        }
    }

    private static boolean isUnreadable(String text) {
        try {
            JsonReader.wireText(text);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    // --- Requests ---

    @Test
    void queryIsBound() {
        byte[] none = new byte[0];
        String bindA = RequestBinding.compute("GET", "/search?q=a", none);
        assertNotEquals(bindA, RequestBinding.compute("GET", "/search?q=b", none));
        assertNotEquals(bindA, RequestBinding.compute("GET", "/search", none));
        var asked = HttpWire.request(null, null, null, "GET", "/search?q=a", none, "orders", null, null);
        assertEquals(bindA, asked.expectedBind());
        assertNotEquals(RequestBinding.compute("GET", "/search", none), asked.expectedBind());

        Stamper.Stamped s = sent(Block.EMPTY, bindA);
        String chain = HttpWire.encodeChain(s.chain());
        String proof = HttpWire.encodeProof(s.proof());
        assertEquals(ReasonCode.OK, verifier().verify(
                HttpWire.request(chain, proof, null, "GET", "/search?q=a", none, "payment", null, null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpWire.request(chain, proof, null, "GET", "/search?q=b", none, "payment", null, null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpWire.request(chain, proof, null, "GET", "/search", none, "payment", null, null)).reason());
    }

    @Test
    void aTargetWithALoneSurrogateIsBindingMismatchAndDoesNotThrow() {
        byte[] none = new byte[0];
        Stamper.Stamped s = sent(Block.EMPTY, RequestBinding.compute("GET", "/search", none));
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(
                HttpWire.request(HttpWire.encodeChain(s.chain()), HttpWire.encodeProof(s.proof()), null, "GET",
                        "/search\ud800", none, "payment", null, null)).reason());
    }

    @Test
    void malformedHeaders() {
        Stamper.Stamped s = sent(Block.EMPTY);
        String chain = HttpWire.encodeChain(s.chain());
        String proof = HttpWire.encodeProof(s.proof());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(
                HttpWire.request("%%%", proof, null, "POST", "/pay", BODY, "payment", null, null)).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(
                HttpWire.request(null, proof, null, "POST", "/pay", BODY, "payment", null, null)).reason());
        assertEquals(ReasonCode.EXTENSION_MISMATCH, verifier().verify(
                HttpWire.request(chain, proof, "%%%", "POST", "/pay", BODY, "payment", null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(
                HttpWire.request(chain, null, null, "POST", "/pay", BODY, "payment", null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(
                HttpWire.request(chain, "%%%", null, "POST", "/pay", BODY, "payment", null, null)).reason());
        assertEquals("\"malformed\"", HttpWire.decodeChain("%%%"));
        assertNull(HttpWire.decodeChain(" "));
        assertNull(HttpWire.decodeProof("%%%"));
        assertEquals("", HttpWire.request("%%%", null, null, "GET", "/", BODY, "payment", null, null).nonceKey());
    }

    // --- Responses ---

    private String respondHeader(Stamper.Stamped s, int status, Block block) {
        return HttpWire.encodeResponse(respond(s, status, block), block);
    }

    private Stamp respond(Stamper.Stamped s, int status, Block block) {
        return stamper("payment", paymentKey, false).respond(s.chain(), HttpWire.resultHash(status, BODY), RID, block);
    }

    private static List<Block> emptyBlocks(Stamper.Stamped s) {
        return Collections.nCopies(s.chain().size(), Block.EMPTY);
    }

    private HttpWire.ResponseCheck check(Stamper.Stamped s, List<Block> sentBlocks, String header) {
        return HttpWire.verifyResponse(verifier(INFLUENCE), s.chain(), sentBlocks, s.proof(), header, 200, BODY,
                "orders", null);
    }

    private ReasonCode responseReason(Stamper.Stamped s, String envelope) {
        return check(s, emptyBlocks(s), token(envelope)).result().reason();
    }

    @Test
    void aResponseCarriesItsOwnBlock() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, LABELLED);

        assertEquals("{\"block\":" + LABELLED.toJson() + ",\"stamp\":" + stamp.toJson() + "}",
                text(HttpWire.encodeResponse(stamp, LABELLED)));
    }

    @Test
    void aResponseWithoutABlockIsChainMissing() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, Block.EMPTY);

        assertEquals(ReasonCode.OK, responseReason(s, "{\"block\":" + Block.EMPTY.toJson() + ",\"stamp\":"
                + stamp.toJson() + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"stamp\":" + stamp.toJson() + "}"));
    }

    /** Version 3's shape, {labels, stamp}, is not a response header any longer, nor is one with both. */
    @Test
    void aResponseWithLabelsMembersIsChainMissing() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, Block.EMPTY);

        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"labels\":[],\"stamp\":" + stamp.toJson() + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"block\":" + Block.EMPTY.toJson()
                + ",\"labels\":[],\"stamp\":" + stamp.toJson() + "}"));
    }

    @Test
    void aResponseBlockThatDoesNotReadAsABlockIsChainMissing() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, Block.EMPTY);

        for (String block : List.of("{\"items\":{}}", "{\"items\":{\"Influence\":[]},\"requires\":[]}", "[]", "null",
                "{\"items\":{},\"requires\":[\"b\",\"a\"]}")) {
            assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"block\":" + block + ",\"stamp\":"
                    + stamp.toJson() + "}"), block);
        }
    }

    @Test
    void aResponseBlockAlteredIsExtensionMismatch() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, LABELLED);
        Block altered = ContentLabel.block(List.of(new ContentLabel(InfluenceClass.PUBLIC, "cid-1", null)), List.of());

        assertEquals(ReasonCode.EXTENSION_MISMATCH,
                check(s, emptyBlocks(s), HttpWire.encodeResponse(stamp, altered)).result().reason());
        assertEquals(ReasonCode.EXTENSION_MISMATCH,
                check(s, emptyBlocks(s), HttpWire.encodeResponse(stamp, Block.EMPTY)).result().reason(),
                "a block stripped from a response whose stamp commits to one");
    }

    /**
     * The blocks the response is checked with are those sent, then its own: orders' block names influence, so a
     * check that passed only the response's own block, or none, fails check 9a.
     */
    @Test
    void aResponseVerifiesWithTheBlocksSentThenItsOwn() {
        Stamper.Stamped s = sent(ORDERS_BLOCK);

        HttpWire.ResponseCheck check = check(s, List.of(Block.EMPTY, ORDERS_BLOCK), respondHeader(s, 200, LABELLED));

        assertEquals(ReasonCode.OK, check.result().reason());
        assertEquals("payment", check.result().suspectSvc());
        assertEquals(new HandOver.StampItems("payment", List.of(LABELS.get(0).toJson())),
                check.response(Influence.NAME), "the response stamp's own entry");
        assertNull(check.response("other"), "a name the caller does not act on");
        assertEquals(HttpWire.resultHash(200, BODY), check.resultHash());
        assertEquals(ReasonCode.EXTENSION_MISMATCH,
                check(s, emptyBlocks(s), respondHeader(s, 200, LABELLED)).result().reason());
    }

    @Test
    void aResponseWhoseBlocksSentWereAbsentStillVerifies() {
        Stamper.Stamped s = sent(Block.EMPTY);

        HttpWire.ResponseCheck check = check(s, emptyBlocks(s), respondHeader(s, 200, Block.EMPTY));

        assertEquals(ReasonCode.OK, check.result().reason());
        assertEquals(new HandOver.StampItems("payment", null), check.response(Influence.NAME),
                "a block that names nothing");
    }

    @Test
    void responseCheckMissingHeader() {
        Stamper.Stamped s = sent(Block.EMPTY);
        var check = check(s, emptyBlocks(s), null);
        assertEquals(ReasonCode.CHAIN_MISSING, check.result().reason());
        assertNull(check.response(Influence.NAME));
        assertEquals(HttpWire.resultHash(200, BODY), check.resultHash());
    }

    @Test
    void responseCheckStatus() {
        Stamper.Stamped s = sent(Block.EMPTY);
        var check = HttpWire.verifyResponse(verifier(INFLUENCE), s.chain(), emptyBlocks(s), s.proof(),
                respondHeader(s, 200, LABELLED), 500, BODY, "orders", null);
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
        assertNull(check.response(Influence.NAME), "nothing is read from a response that did not verify");
    }

    @Test
    void responseCheckNeverThrows() {
        Stamper.Stamped s = sent(Block.EMPTY);
        for (String header : new String[] {"e30", "%%%", "", token("[]"),
                token("{\"block\":{\"items\":{},\"requires\":[]},\"stamp\":{}}"),
                token("{\"block\":1,\"stamp\":\"x\"}")}) {
            var check = check(s, emptyBlocks(s), header);
            assertEquals(ReasonCode.CHAIN_MISSING, check.result().reason(), header);
            assertNull(check.response(Influence.NAME));
        }
    }

    /**
     * The response header is read from its bytes: only the JCS bytes of {@code {block, stamp}} read. A number where
     * a string belongs, a repeated name, or the members in another order is CHAIN_MISSING.
     */
    @Test
    void responseStampIsJudgedAsSent() {
        Stamper.Stamped s = sent(Block.EMPTY);
        String good = respond(s, 200, Block.EMPTY).toJson();
        String huge = good.replace("\"svc\":\"payment\"", "\"svc\":1e400");
        String block = Block.EMPTY.toJson();
        assertEquals(ReasonCode.OK, responseReason(s, "{\"block\":" + block + ",\"stamp\":" + good + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"block\":" + block + ",\"stamp\":" + huge + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"block\":" + block + ",\"stamp\":" + huge + ",\"stamp\":" + good + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s, "{\"stamp\":" + good + ",\"block\":" + block + "}"));
    }

    @Test
    void aResponseHeaderWithAnExtraMemberIsChainMissing() {
        Stamper.Stamped s = sent(Block.EMPTY);
        Stamp stamp = respond(s, 200, Block.EMPTY);
        String block = Block.EMPTY.toJson();
        assertEquals(ReasonCode.OK, responseReason(s, "{\"block\":" + block + ",\"stamp\":" + stamp.toJson() + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"block\":" + block + ",\"extra\":1,\"stamp\":" + stamp.toJson() + "}"));
        assertEquals(ReasonCode.CHAIN_MISSING, responseReason(s,
                "{\"block\":{\"extra\":1,\"items\":{},\"requires\":[]},\"stamp\":" + stamp.toJson() + "}"));
    }

    @Test
    void responseCheckRidTheBindingCannotCarry() {
        // A newline in the rid cannot be bound, so a verifier cannot compute the binding and must reject.
        Stamper.Stamped first = new Stamper("gateway", "gw-1", gatewayKey.getPrivate(), true, () -> "a\nb", () -> NOW)
                .next(List.of(), "orders", "b1", Block.EMPTY, policy.bundles().get("gateway"));
        Stamper.Stamped s = stamper("orders", ordersKey, false).next(first.chain(), "payment", "b2", Block.EMPTY,
                policy.bundles().get("orders"));
        Stamp stamp = Stamp.sign("payment", "payment-1", "a\nb", NOW, "", "orders", "x", "",
                s.chain().get(1).sig(), paymentKey.getPrivate());
        var check = check(s, emptyBlocks(s), HttpWire.encodeResponse(stamp, Block.EMPTY));
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
    }

    @Test
    void responseCheckLoneSurrogateRid() {
        // Unsigned stamps are fine here: the binding is computed before any signature is looked at.
        Stamp first = new Stamp("gateway", "gw-1", "\uD800", NOW, "", "orders", "b1", "", "", "");
        Stamp second = new Stamp("orders", "ord-1", "\uD800", NOW, "", "payment", "b2", "", "x", "");
        Stamp response = Stamp.sign("payment", "payment-1", RID, NOW, "", "orders", "x", "", "y",
                paymentKey.getPrivate());
        var check = HttpWire.verifyResponse(verifier(), List.of(first, second), List.of(Block.EMPTY, Block.EMPTY),
                null, HttpWire.encodeResponse(response, Block.EMPTY), 200, BODY, "orders", null);
        assertEquals(ReasonCode.BINDING_MISMATCH, check.result().reason());
    }

    @Test
    void verifyResponseKeyKeepsTheOperation() {
        List<String> spent = new ArrayList<>();
        Verifier opsVerifier = verifier(ops, recording(spent), ExtensionSettings.NONE);
        Stamper.Stamped s = sent(ops, "payment#charge", Block.EMPTY, RequestBinding.compute("POST", "/pay", BODY));
        String header = respondHeader(s, 200, Block.EMPTY);

        var first = HttpWire.verifyResponse(opsVerifier, s.chain(), emptyBlocks(s), s.proof(), header, 200, BODY,
                "orders", null);
        var again = HttpWire.verifyResponse(opsVerifier, s.chain(), emptyBlocks(s), s.proof(), header, 200, BODY,
                "orders", null);

        assertEquals(ReasonCode.OK, first.result().reason());
        assertEquals(ReasonCode.REPLAY, again.result().reason(), "the key [rid, payment#charge, resp] was spent");
        assertEquals(List.of("[\"rid-1\",\"payment#charge\",\"resp\"]", "[\"rid-1\",\"payment#charge\",\"resp\"]"),
                spent);
    }

    @Test
    void resultHashBindsStatusAndBody() {
        assertNotEquals(HttpWire.resultHash(200, BODY), HttpWire.resultHash(201, BODY));
        assertNotEquals(HttpWire.resultHash(200, BODY), HttpWire.resultHash(200, new byte[0]));
        assertEquals(Base64Url.encode(Crypto.sha256("http-response\n200\n".getBytes(StandardCharsets.UTF_8))),
                HttpWire.resultHash(200, new byte[0]));
    }
}
