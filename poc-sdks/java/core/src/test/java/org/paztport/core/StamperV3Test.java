// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The v3 stamper's output, checked by the live verifier it feeds: calls, committed influence and responses. */
class StamperV3Test {

    private static final long NOW = 1_000_000L;
    private static final String RID = "rid-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeyPair gatewayKey = Crypto.generateEd25519KeyPair();
    private final KeyPair ordersKey = Crypto.generateEd25519KeyPair();
    private final KeyPair paymentKey = Crypto.generateEd25519KeyPair();
    private final KeyPair policyKey = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment")), 4, policyKey.getPrivate());

    private StamperV3 stamper(String svc, KeyPair key, boolean origin) {
        return new StamperV3(svc, svc + "-1", key.getPrivate(), origin, () -> RID, () -> NOW);
    }

    private VerifierV3 verifier() {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gatewayKey.getPublic(), "orders", ordersKey.getPublic(),
                        "payment", paymentKey.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), Set.of("gateway"), "",
                new InMemoryNonceCache(60_000), () -> NOW, 30_000, 300_000));
    }

    private static ArrayNode json(List<StampV3> chain) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        chain.forEach(s -> a.add(s.toJson()));
        return a;
    }

    private static JsonNode json(MerkleProof proof) {
        return MAPPER.valueToTree(proof);
    }

    private StamperV3.Stamped toOrders(String bind, List<InfluenceEntry> influence) {
        return stamper("gateway", gatewayKey, true).next(List.of(), "orders", bind, influence,
                policy.bundles().get("gateway"));
    }

    private StamperV3.Stamped toPayment(StamperV3.Stamped fromGateway, List<InfluenceEntry> influence) {
        return stamper("orders", ordersKey, false).next(fromGateway.chain(), "payment", "b2", influence,
                policy.bundles().get("orders"));
    }

    private StamperV3.Stamped toPayment(StamperV3.Stamped fromGateway) {
        return toPayment(fromGateway, List.of());
    }

    /**
     * Why a service must verify a chain before it attests a response to it. A response stamp is shaped like a
     * request stamp, and {@link StamperV3#respond} checks nothing: on a forged one-stamp chain with an empty
     * {@code sig} (which parses, since {@code ""} is canonical base64url), the origin's response has {@code prev}
     * {@code ""} and so is a valid origin stamp, addressed to whichever service the forgery named. That service, once
     * handed it as a chain, appends its own stamp, and the receiver after it accepts a request tree the origin never
     * started. The Spring filter therefore attests only a chain it verified, and an origin never attests.
     */
    @Test
    void aResponseToAnUncheckedChainIsAValidOriginStamp() {
        List<StampV3> forged = List.of(new StampV3("orders", "x", RID, NOW, "", "x", "b",
                Influence.commit(List.of()), "", ""));

        StampV3 minted = stamper("gateway", gatewayKey, true).respond(forged, "h", RID, List.of());
        StamperV3.Stamped driven = stamper("orders", ordersKey, false).next(List.of(minted), "payment", "b2",
                List.of(), policy.bundles().get("orders"));

        VerifyResult r = verifier().verify(new VerifyInputV3(json(driven.chain()), "b2",
                JsonNodeFactory.instance.arrayNode(), json(driven.proof()), "payment", true, RID + "|orders|req",
                new Peer("orders", "10.0.0.3")));
        assertEquals(ReasonCode.OK, r.reason(), "the attack the filter's rule closes");
    }

    @Test
    void hopsVerify() {
        StamperV3.Stamped first = toOrders("b1", List.of());
        assertNull(first.proof());
        StamperV3.Stamped second = toPayment(first);
        assertEquals(2, second.chain().size());
        VerifyResult r = verifier().verify(new VerifyInputV3(json(second.chain()), "b2",
                JsonNodeFactory.instance.arrayNode(), json(second.proof()), "payment", true,
                RID + "|orders|req", null));
        assertEquals(ReasonCode.OK, r.reason());
    }

    @Test
    void influenceCommitted() {
        List<InfluenceEntry> influence = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "db:users", "h1", "cid-1", "alice"));
        StamperV3.Stamped second = toPayment(toOrders("b1", List.of()), influence);
        assertEquals(Influence.commit(influence), second.chain().get(1).infl());
        assertEquals(ReasonCode.OK, verifier().verify(new VerifyInputV3(json(second.chain()), "b2",
                Influence.toJson(influence), json(second.proof()), "payment", true, RID + "|orders|a", null))
                .reason());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH, verifier().verify(new VerifyInputV3(json(second.chain()), "b2",
                JsonNodeFactory.instance.arrayNode(), json(second.proof()), "payment", true, RID + "|orders|b",
                null)).reason());
    }

    /** payment answers orders; the labels and the proof orders sent are what the caller verifies against. */
    private record Response(List<StampV3> sent, MerkleProof proof, List<ContentLabel> labels, StampV3 stamp) {
        JsonNode chain() {
            ArrayNode a = json(sent);
            a.add(stamp.toJson());
            return a;
        }
    }

    private Response response() {
        StamperV3.Stamped second = toPayment(toOrders("b1", List.of()));
        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-9", "alice"));
        StampV3 stamp = stamper("payment", paymentKey, false).respond(second.chain(), "hash-1", RID, labels);
        return new Response(second.chain(), second.proof(), labels, stamp);
    }

    private VerifyResult verifyResponse(Response r, String bind, String receiver) {
        return verifier().verify(new VerifyInputV3(r.chain(), bind, JsonNodeFactory.instance.arrayNode(),
                json(r.proof()), receiver, false, RID + "|payment|resp", null));
    }

    @Test
    void responseVerifies() {
        Response r = response();
        assertEquals("orders", r.stamp().rcv());
        assertEquals(Influence.commit(List.of()), r.stamp().infl());
        assertEquals(ReasonCode.OK,
                verifyResponse(r, Bindings.response("hash-1", RID, r.labels()), "orders").reason());
    }

    @Test
    void responseTamperedLabels() {
        Response r = response();
        List<ContentLabel> other = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-9", "mallory"));
        assertEquals(ReasonCode.BINDING_MISMATCH,
                verifyResponse(r, Bindings.response("hash-1", RID, other), "orders").reason());
    }

    @Test
    void responseToWrongCaller() {
        Response r = response();
        assertEquals(ReasonCode.BINDING_MISMATCH,
                verifyResponse(r, Bindings.response("hash-1", RID, r.labels()), "gateway").reason());
    }

    @Test
    void nonOriginNeedsChain() {
        StamperV3 orders = stamper("orders", ordersKey, false);
        assertThrows(IllegalStateException.class, () -> orders.next(List.of(), "payment", "b", List.of(), null));
        assertThrows(IllegalStateException.class, () -> orders.respond(List.of(), "h", RID, List.of()));
    }

    @Test
    void labelsRoundTripAndRefuseEmptyOwner() throws Exception {
        ContentLabel fresh = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        ArrayNode wire = JsonNodeFactory.instance.arrayNode().add(fresh.toJson());
        assertEquals(List.of(fresh), ContentLabel.parseAll(wire));
        assertEquals(22, ContentLabel.fresh(InfluenceClass.PUBLIC, null).cid().length());
        assertEquals(new InfluenceEntry(InfluenceClass.PRIVATE, "http:x", "h", fresh.cid(), "alice"),
                fresh.toEntry("http:x", "h"));
        JsonNode bad = MAPPER.readTree("[{\"cls\":\"private\",\"cid\":\"c\",\"owner\":\"\"}]");
        assertThrows(IllegalArgumentException.class, () -> ContentLabel.parseAll(bad));
        assertThrows(IllegalArgumentException.class, () -> Bindings.response("h", "a\nb", List.of()));
    }

}
