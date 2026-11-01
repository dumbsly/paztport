// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class MerkleTreeTest {

    private static final int DEPTH = 8;

    private static final List<String> ROUTES = List.of(
            "gateway/orders/payment",
            "gateway/orders",
            "gateway/search");

    private static List<MerkleLeaf> saltedLeaves() {
        List<MerkleLeaf> leaves = new ArrayList<>();
        for (String route : ROUTES) {
            leaves.add(new MerkleLeaf(Crypto.randomBytes(16), route));
        }
        return leaves;
    }

    @Test
    void everyRealLeafHasAProofThatVerifiesToRoot() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        for (String route : ROUTES) {
            MerkleProof proof = tree.proofFor(route);
            assertTrue(proof.verify(route, tree.root()), "proof must verify for " + route);
        }
    }

    @Test
    void aLeafOverALoneSurrogateRefuses() {
        byte[] salt = Crypto.randomBytes(16);
        assertThrows(IllegalArgumentException.class, () -> MerkleHash.leaf(salt, "a/\ud800"));
        assertEquals(32, MerkleHash.leaf(salt, "a/\ud83d\ude00").length);
    }

    @Test
    void aLoneSurrogateRouteDoesNotVerifyAndDoesNotThrow() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        assertFalse(tree.proofFor(ROUTES.get(0)).verify("gateway/\ud800", tree.root()));
    }

    @Test
    void explicitSlotsProveAndPlace() {
        List<MerkleLeaf> leaves = saltedLeaves().subList(0, 2);
        MerkleTree tree = MerkleTree.build(leaves, DEPTH, "v1", new int[] {5, 200});
        for (MerkleLeaf leaf : leaves) {
            assertTrue(tree.proofFor(leaf.path()).verify(leaf.path(), tree.root()));
        }
        // Slot 5 is binary 00000101, least significant bit first.
        assertEquals("RLRLLLLL", tree.proofFor(leaves.get(0).path()).dirs());
    }

    @Test
    void duplicateOrOutOfRangeSlotsRefused() {
        List<MerkleLeaf> two = saltedLeaves().subList(0, 2);
        assertThrows(IllegalArgumentException.class, () -> MerkleTree.build(two, DEPTH, "v1", new int[] {3, 3}));
        List<MerkleLeaf> one = saltedLeaves().subList(0, 1);
        assertThrows(IllegalArgumentException.class, () -> MerkleTree.build(one, DEPTH, "v1", new int[] {256}));
    }

    @Test
    void proofSiblingsAreAlwaysDepthLongRegardlessOfLeafCount() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");
        assertEquals(DEPTH, proof.siblings().size());
        assertEquals(DEPTH, proof.dirs().length());
    }

    @Test
    void wrongSaltDoesNotVerify() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");

        MerkleProof forged = new MerkleProof(
                Base64Url.encode(Crypto.randomBytes(16)), proof.siblings(), proof.dirs(), proof.rootId());
        assertFalse(forged.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void routeNotInTreeCannotBeProven() {
        // search can reach payment on the network but has no such leaf: with a
        // salted tree it cannot compute a membership proof for this route.
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof stolen = tree.proofFor("gateway/search");

        // Reusing another route's proof for the illicit route fails.
        assertFalse(stolen.verify("gateway/search/payment", tree.root()));
    }

    @Test
    void tamperedSiblingDoesNotVerify() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");

        List<String> siblings = new ArrayList<>(proof.siblings());
        siblings.set(0, Base64Url.encode(Crypto.randomBytes(32)));
        MerkleProof tampered = new MerkleProof(proof.leafSalt(), siblings, proof.dirs(), proof.rootId());

        assertFalse(tampered.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void saltAbsorbingPartOfThePathDoesNotProveAShorterRoute() {
        // leaf = H(0x00 || salt || path), so salt || "gateway/" with path "orders/payment"
        // hashes the same bytes. A fixed salt length closes the re-split.
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");
        byte[] salt = Base64Url.decode(proof.leafSalt());
        byte[] prefix = "gateway/".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] resalted = new byte[salt.length + prefix.length];
        System.arraycopy(salt, 0, resalted, 0, salt.length);
        System.arraycopy(prefix, 0, resalted, salt.length, prefix.length);
        MerkleProof forged = new MerkleProof(Base64Url.encode(resalted), proof.siblings(), proof.dirs(), proof.rootId());

        assertFalse(forged.verify("orders/payment", tree.root()));
    }

    @Test
    void shortSaltDoesNotVerify() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");
        byte[] salt = Base64Url.decode(proof.leafSalt());
        byte[] shorter = java.util.Arrays.copyOf(salt, salt.length - 1);
        MerkleProof forged = new MerkleProof(Base64Url.encode(shorter), proof.siblings(), proof.dirs(), proof.rootId());

        assertFalse(forged.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void siblingOfWrongLengthDoesNotVerify() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");
        List<String> siblings = new ArrayList<>(proof.siblings());
        siblings.set(0, Base64Url.encode(Crypto.randomBytes(31)));
        MerkleProof bad = new MerkleProof(proof.leafSalt(), siblings, proof.dirs(), proof.rootId());

        assertFalse(bad.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void dirsOtherThanLAndRDoNotVerify() {
        // Previously any non-'L' character was read as 'R'.
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/search"); // index 2: dirs start "R"
        String dirs = "X" + proof.dirs().substring(1);
        MerkleProof bad = new MerkleProof(proof.leafSalt(), proof.siblings(), dirs, proof.rootId());

        assertFalse(bad.verify("gateway/search", tree.root()));
    }

    @Test
    void undecodableSiblingDoesNotVerifyOrThrow() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");
        List<String> siblings = new ArrayList<>(proof.siblings());
        siblings.set(0, "!!not-base64!!");
        MerkleProof bad = new MerkleProof(proof.leafSalt(), siblings, proof.dirs(), proof.rootId());

        assertFalse(bad.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void proofEncodeDecodeRoundTrips() {
        MerkleTree tree = MerkleTree.build(saltedLeaves(), DEPTH, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders/payment");

        MerkleProof decoded = MerkleProof.decode(proof.encode());
        assertEquals(proof, decoded);
        assertTrue(decoded.verify("gateway/orders/payment", tree.root()));
    }

    @Test
    void aProofIsReadOnlyFromItsJcsBytes() {
        MerkleProof proof = MerkleTree.build(saltedLeaves(), DEPTH, "v1").proofFor("gateway/orders/payment");
        String jcs = proof.toJson();
        assertEquals(proof, MerkleProof.parse(jcs));
        String wireOrder = "{\"leafSalt\":\"" + proof.leafSalt() + "\",\"siblings\":[\""
                + String.join("\",\"", proof.siblings()) + "\"],\"dirs\":\"" + proof.dirs() + "\",\"rootId\":\""
                + proof.rootId() + "\"}";
        // in JCS order, so it is refused for the member alone
        String extra = jcs.replace(",\"leafSalt\"", ",\"extra\":1,\"leafSalt\"");
        for (String bad : new String[] {wireOrder, " " + jcs, extra}) {
            assertThrows(IllegalArgumentException.class, () -> MerkleProof.parse(bad), bad);
            assertThrows(IllegalArgumentException.class,
                    () -> MerkleProof.decode(Base64Url.encode(bad.getBytes(StandardCharsets.UTF_8))), bad);
        }
    }

    @Test
    void buildRejectsMoreLeavesThanDepthAllows() {
        // depth 1 -> 2 slots; three routes do not fit.
        assertThrows(IllegalArgumentException.class, () -> MerkleTree.build(saltedLeaves(), 1, "v1"));
    }

    @Test
    void leafAndNodeHashingAreDomainSeparated() {
        // A leaf hash and a node hash over the same 64 bytes must differ,
        // because of the 0x00 / 0x01 domain prefixes.
        byte[] left = Crypto.randomBytes(32);
        byte[] right = Crypto.randomBytes(32);
        byte[] asNode = MerkleHash.node(left, right);

        byte[] concat = new byte[64];
        System.arraycopy(left, 0, concat, 0, 32);
        System.arraycopy(right, 0, concat, 32, 32);
        byte[] asLeaf = MerkleHash.leaf(left, new String(right, java.nio.charset.StandardCharsets.ISO_8859_1));

        assertFalse(java.util.Arrays.equals(asNode, asLeaf));
    }
}
