// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;

class PolicyBuilderTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final int DEPTH = 8;

    private static final List<List<String>> POC_PATHS = List.of(
            List.of("gateway", "orders", "payment"),
            List.of("gateway", "orders"),
            List.of("gateway", "search"));

    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private PolicyBuilder.Result build(List<List<String>> paths) {
        return PolicyBuilder.build(paths, DEPTH, NOT_AFTER, policy.getPrivate());
    }

    @Test
    void refusesARouteNodeTheSpecForbidsAnywhereInARoute() {
        for (String bad : List.of("", ".", "..", "a/b", "a\\b", "a|b", "a\ud800")) {
            assertThrows(IllegalArgumentException.class,
                    () -> build(List.of(List.of("gateway", "orders"), List.of("gateway", bad, "payment"))), bad);
            assertThrows(IllegalArgumentException.class, () -> build(List.of(List.of(bad, "orders"))), bad);
        }
    }

    @Test
    void proofsArePartitionedToTheSecondToLastHop() {
        PolicyBuilder.Result r = build(POC_PATHS);

        assertEquals(Set.of("gateway/orders", "gateway/search"), r.bundles().get("gateway").proofs().keySet());
        assertEquals(Set.of("gateway/orders/payment"), r.bundles().get("orders").proofs().keySet());
    }

    @Test
    void searchBundleContainsNoRouteEndingAtPayment() {
        PolicyBuilder.Result r = build(POC_PATHS);

        var search = r.bundles().get("search");
        assertTrue(search.proofs().isEmpty(), "search must hold no proofs at all");
        assertTrue(search.proofs().keySet().stream().noneMatch(route -> route.endsWith("/payment")));
    }

    @Test
    void everyServiceInaPathGetsABundleEvenIfEmpty() {
        PolicyBuilder.Result r = build(POC_PATHS);
        assertEquals(Set.of("gateway", "orders", "payment", "search"), r.bundles().keySet());
        assertTrue(r.bundles().get("payment").proofs().isEmpty());
    }

    @Test
    void everyEmittedProofVerifiesAgainstTheSignedRoot() {
        PolicyBuilder.Result r = build(POC_PATHS);
        byte[] root = r.signedRoot().rootBytes();

        for (var bundle : r.bundles().values()) {
            for (var entry : bundle.proofs().entrySet()) {
                MerkleProof proof = entry.getValue();
                assertEquals(r.signedRoot().rootId(), proof.rootId());
                assertTrue(proof.verify(entry.getKey(), root), "proof failed for " + entry.getKey());
            }
        }
    }

    @Test
    void signedRootVerifiesWithThePolicyPublicKey() {
        PolicyBuilder.Result r = build(POC_PATHS);
        assertTrue(r.signedRoot().verify(policy.getPublic()));
    }

    @Test
    void rootIdIsRandomPerBuild() {
        String first = build(POC_PATHS).signedRoot().rootId();
        String second = build(POC_PATHS).signedRoot().rootId();
        assertNotEquals(first, second);
        assertTrue(first.matches("^v[0-9a-f]{12}$"), first);
        assertTrue(second.matches("^v[0-9a-f]{12}$"), second);
    }

    @Test
    void slotsAreNotPolicyOrder() {
        boolean moved = false;
        for (int i = 0; i < 20 && !moved; i++) {
            PolicyBuilder.Result r = build(POC_PATHS);
            String dirs = r.bundles().get("orders").proofs().get("gateway/orders/payment").dirs();
            moved = !dirs.equals("LLLLLLLL");
        }
        assertTrue(moved, "the first route stayed in slot 0 across 20 builds");
    }

    @Test
    void addingGatewaySearchPaymentChangesRootIdAndGivesSearchAProof() {
        // Scenario 10 pre-flight: policy drives behaviour.
        PolicyBuilder.Result before = build(POC_PATHS);

        List<List<String>> widened = List.of(
                List.of("gateway", "orders", "payment"),
                List.of("gateway", "orders"),
                List.of("gateway", "search"),
                List.of("gateway", "search", "payment"));
        PolicyBuilder.Result after = build(widened);

        assertNotEquals(before.signedRoot().rootId(), after.signedRoot().rootId());
        assertEquals(Set.of("gateway/search/payment"), after.bundles().get("search").proofs().keySet());
        assertTrue(after.bundles().get("search").proofs().get("gateway/search/payment")
                .verify("gateway/search/payment", after.signedRoot().rootBytes()));
    }

    @Test
    void rejectsSingleNodeRouteWithNoCaller() {
        assertFalse(tryBuild(List.of(List.of("gateway"))));
    }

    private boolean tryBuild(List<List<String>> paths) {
        try {
            build(paths);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Test
    void holderIsTheServicePart() {
        PolicyBuilder.Result r = build(List.of(List.of("gateway", "orders#createOrder", "payment#charge")));

        assertEquals(Set.of("gateway/orders#createOrder/payment#charge"), r.bundles().get("orders").proofs().keySet());
        assertEquals(Set.of("gateway", "orders", "payment"), r.bundles().keySet());
    }

    @Test
    void opsRouteGoesToTheServiceAndItsCallers() {
        PolicyBuilder.Result r = build(List.of(
                List.of("orders", "ops:H"),
                List.of("gateway", "orders#getOrder"),
                List.of("gateway", "tickets"),
                List.of("tickets", "assistant")));

        assertTrue(r.bundles().get("orders").proofs().containsKey("orders/ops:H"));
        assertTrue(r.bundles().get("gateway").proofs().containsKey("orders/ops:H"));
        assertFalse(r.bundles().get("tickets").proofs().containsKey("orders/ops:H"));
        assertFalse(r.bundles().get("assistant").proofs().containsKey("orders/ops:H"));
        assertFalse(r.bundles().containsKey("ops:H"));
    }

    @Test
    void refusesAnOperationNodeBeforeTheLastWithABadPart() {
        assertThrows(IllegalArgumentException.class, () -> build(List.of(List.of("gateway", "orders#", "payment"))));
        assertThrows(IllegalArgumentException.class, () -> build(List.of(List.of("a#b#c", "payment"))));
    }
}
