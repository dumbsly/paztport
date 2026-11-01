// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.util.ArrayList;
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
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.core.verify.VerifyResult;

/** The v3 stamper's output, checked by the live verifier it feeds: calls, committed influence and responses. */
class StamperV3Test {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final String RID = "rid-1";

    private final KeyPair gatewayKey = Crypto.generateEd25519KeyPair();
    private final KeyPair ordersKey = Crypto.generateEd25519KeyPair();
    private final KeyPair paymentKey = Crypto.generateEd25519KeyPair();
    private final KeyPair policyKey = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment")), 4, NOT_AFTER, policyKey.getPrivate());

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

    private static String json(List<StampV3> chain) {
        return Chains.toJson(chain);
    }

    private static String json(MerkleProof proof) {
        return proof == null ? null : proof.toJson();
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
                "[]", json(driven.proof()), "payment", true, RID + "|orders|req",
                new Peer("orders", "10.0.0.3")));
        assertEquals(ReasonCode.OK, r.reason(), "the attack the filter's rule closes");
    }

    private static final String SESS = "sess-1";
    private static final List<InfluenceEntry> BOUNDARY_INFLUENCE = List.of(
            new InfluenceEntry(InfluenceClass.PRIVATE, "db:orders", "h1", "cid-1", "alice"));

    private final PolicyBuilder.Result egress = PolicyBuilder.build(
            List.of(List.of("payment", "psp")), 4, NOT_AFTER, policyKey.getPrivate());

    private StamperV3.Stamped boundary(String sess, ProofBundle bundle) {
        StampV3 inbound = toPayment(toOrders("b1", List.of())).chain().get(1);
        return stamper("payment", paymentKey, false).boundary(List.of(inbound), sess, "psp", "b3",
                BOUNDARY_INFLUENCE, bundle);
    }

    @Test
    void boundaryStampFields() {
        StamperV3.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(1, b.chain().size());
        StampV3 s = b.chain().get(0);
        assertEquals("payment", s.svc());
        assertEquals("payment-1", s.inst());
        assertEquals(RID, s.rid());
        assertEquals(NOW, s.ts());
        assertEquals(SESS, s.sess());
        assertEquals("psp", s.rcv());
        assertEquals("b3", s.bind());
        assertEquals(Influence.commit(BOUNDARY_INFLUENCE), s.infl());
        assertEquals("", s.prev());
    }

    @Test
    void boundaryProofForEgressRoute() {
        StamperV3.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(egress.signedRoot().rootId(), b.proof().rootId());
        assertNull(boundary(SESS, policy.bundles().get("payment")).proof());
    }

    @Test
    void boundaryRefusesEmptySess() {
        assertThrows(IllegalArgumentException.class, () -> boundary("", egress.bundles().get("payment")));
        assertThrows(IllegalArgumentException.class, () -> boundary(null, egress.bundles().get("payment")));
    }

    @Test
    void boundaryRefusesNoChain() {
        StamperV3 payment = stamper("payment", paymentKey, false);
        assertThrows(IllegalStateException.class,
                () -> payment.boundary(null, SESS, "psp", "b3", List.of(), null));
        assertThrows(IllegalStateException.class,
                () -> payment.boundary(List.of(), SESS, "psp", "b3", List.of(), null));
    }

    private VerifyResult verifyAtPartner(StamperV3.Stamped b, String sess) {
        String pin = Base64Url.encode(Crypto.encodePublicKey(policyKey.getPublic()));
        KeyringFile ring = KeyringFile.sign(Map.of("payment", Base64Url.encode(Crypto.encodePublicKey(
                paymentKey.getPublic()))), pin, NOT_AFTER, policyKey.getPrivate());
        VerifierV3 partner = new VerifierV3(VerifierConfigV3.pinned(ring, egress.signedRoot(), pin,
                Set.of("payment"), sess, new InMemoryNonceCache(60_000), () -> NOW, 30_000, 300_000));
        return partner.verify(new VerifyInputV3(json(b.chain()), "b3", Influence.toJson(BOUNDARY_INFLUENCE),
                json(b.proof()), "psp", true, RID + "|payment|req", new Peer("payment", "10.0.0.1")));
    }

    @Test
    void boundaryVerifiesAsPartner() {
        StamperV3.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(ReasonCode.OK, verifyAtPartner(b, SESS).reason());
        assertEquals(ReasonCode.SESSION_UNKNOWN, verifyAtPartner(b, "").reason());
    }

    @Test
    void hopsVerify() {
        StamperV3.Stamped first = toOrders("b1", List.of());
        assertNull(first.proof());
        StamperV3.Stamped second = toPayment(first);
        assertEquals(2, second.chain().size());
        VerifyResult r = verifier().verify(new VerifyInputV3(json(second.chain()), "b2",
                "[]", json(second.proof()), "payment", true,
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
                "[]", json(second.proof()), "payment", true, RID + "|orders|b",
                null)).reason());
    }

    /** payment answers orders; the labels and the proof orders sent are what the caller verifies against. */
    private record Response(List<StampV3> sent, MerkleProof proof, List<ContentLabel> labels, StampV3 stamp) {
        String chain() {
            List<StampV3> all = new ArrayList<>(sent);
            all.add(stamp);
            return Chains.toJson(all);
        }
    }

    private Response response() {
        StamperV3.Stamped second = toPayment(toOrders("b1", List.of()));
        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-9", "alice"));
        StampV3 stamp = stamper("payment", paymentKey, false).respond(second.chain(), "hash-1", RID, labels);
        return new Response(second.chain(), second.proof(), labels, stamp);
    }

    private VerifyResult verifyResponse(Response r, String bind, String receiver) {
        return verifier().verify(new VerifyInputV3(r.chain(), bind, "[]",
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
    void aLabelListHasExactlyTheLabelMembersInJcsOrder() {
        assertEquals(1, ContentLabel.parseAll("[{\"cid\":\"c\",\"cls\":\"public\"}]").size());
        for (String bad : new String[] {"[{\"cid\":\"c\",\"cls\":\"public\",\"extra\":1}]",
                "[{\"cls\":\"public\",\"cid\":\"c\"}]", "[{\"cid\":\"c\"}]", "[{\"cid\":\"c\",\"cls\":\"bogus\"}]",
                "[ {\"cid\":\"c\",\"cls\":\"public\"}]", "{}", "[1]"}) {
            assertThrows(IllegalArgumentException.class, () -> ContentLabel.parseAll(bad), bad);
        }
    }

    @Test
    void labelsRoundTripAndRefuseEmptyOwner() throws Exception {
        ContentLabel fresh = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        assertEquals(List.of(fresh), ContentLabel.parseAll(ContentLabel.toJson(List.of(fresh))));
        assertEquals(22, ContentLabel.fresh(InfluenceClass.PUBLIC, null).cid().length());
        assertEquals(new InfluenceEntry(InfluenceClass.PRIVATE, "http:x", "h", fresh.cid(), "alice"),
                fresh.toEntry("http:x", "h"));
        String bad = "[{\"cid\":\"c\",\"cls\":\"private\",\"owner\":\"\"}]";
        assertThrows(IllegalArgumentException.class, () -> ContentLabel.parseAll(bad));
        assertThrows(IllegalArgumentException.class, () -> Bindings.response("h", "a\nb", List.of()));
    }

}
