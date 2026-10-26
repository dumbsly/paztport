// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OutboundStamperTest {

    private static final long NOW = 1_000_000L;

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private final MerkleTree tree = MerkleTree.build(
            List.of(
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders/payment"),
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders"),
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/search")),
            8, "v1");
    private final SignedRoot signedRoot = SignedRoot.sign(tree.root(), "v1", policy.getPrivate());

    private final ProofBundle gatewayBundle = new ProofBundle("gateway", "v1", Map.of(
            "gateway/orders", tree.proofFor("gateway/orders"),
            "gateway/search", tree.proofFor("gateway/search")));
    private final ProofBundle ordersBundle = new ProofBundle("orders", "v1", Map.of(
            "gateway/orders/payment", tree.proofFor("gateway/orders/payment")));

    private OutboundStamper gatewayStamper() {
        return new OutboundStamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW);
    }

    private OutboundStamper ordersStamper() {
        return new OutboundStamper("orders", "ord-1", orders.getPrivate(), false, () -> "rid-X", () -> 9L);
    }

    @Test
    void originProducesSingleStampWithFreshRidEmptyPrevAndItsProof() {
        OutboundStamper.StampedHeaders h =
                gatewayStamper().stamp(null, "bind:/orders", "orders", gatewayBundle);

        List<Stamp> stamps = PathChain.decode(h.chainHeader()).stamps();
        assertEquals(1, stamps.size());
        assertEquals("gateway", stamps.get(0).svc());
        assertEquals("rid-1", stamps.get(0).rid());
        assertEquals(NOW, stamps.get(0).ts());
        assertEquals("", stamps.get(0).prev());
        assertNotNull(h.proofHeader(), "gateway holds the gateway/orders proof");
    }

    @Test
    void appendLinksPrevAndCarriesOriginRidAndTs() {
        OutboundStamper.StampedHeaders gw =
                gatewayStamper().stamp(null, "bind:/orders", "orders", gatewayBundle);
        PathChain inbound = PathChain.decode(gw.chainHeader());

        OutboundStamper.StampedHeaders h =
                ordersStamper().stamp(inbound, "bind:/pay", "payment", ordersBundle);

        List<Stamp> stamps = PathChain.decode(h.chainHeader()).stamps();
        assertEquals(2, stamps.size());
        assertEquals("orders", stamps.get(1).svc());
        assertEquals(inbound.stamps().get(0).sig(), stamps.get(1).prev());
        assertEquals("rid-1", stamps.get(1).rid(), "origin rid carried, not the stamper's own supplier");
        assertEquals(NOW, stamps.get(1).ts(), "origin ts carried unchanged");
    }

    @Test
    void nonOriginWithoutInboundChainFailsClosed() {
        assertThrows(IllegalStateException.class,
                () -> ordersStamper().stamp(null, "bind:/pay", "payment", ordersBundle));
    }

    @Test
    void noProofAttachedWhenBundleLacksTheRoute() {
        // gateway calling payment directly is not an allowed route; its bundle has no such proof.
        OutboundStamper.StampedHeaders h =
                gatewayStamper().stamp(null, "bind:/pay", "payment", gatewayBundle);
        assertNull(h.proofHeader());
    }

    @Test
    void stamperOutputVerifiesEndToEndAtPayment() {
        // gateway -> orders -> payment, built entirely by the stamper, accepted by the core Verifier.

        OutboundStamper.StampedHeaders gw =
                gatewayStamper().stamp(null, "bind:/orders", "orders", gatewayBundle);
        PathChain inbound = PathChain.decode(gw.chainHeader());
        OutboundStamper.StampedHeaders ord =
                ordersStamper().stamp(inbound, "bind:/pay", "payment", ordersBundle);

        VerifierConfig cfg = VerifierConfig.pinned(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", orders.getPublic())),
                signedRoot, policy.getPublic(), Set.of("gateway"), 5000,
                new InMemoryNonceCache(), () -> NOW);

        VerifyRequest req = new VerifyRequest(ord.chainHeader(), ord.proofHeader(), "bind:/pay", "payment", null);
        assertTrue(new Verifier(cfg).verify(req).ok());
    }
}
