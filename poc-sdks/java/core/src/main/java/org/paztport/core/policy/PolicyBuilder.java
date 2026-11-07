// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.crypto.Crypto;

/**
 * Turns a list of allowed routes into a signed Merkle root and per-service proof
 * bundles. Pure logic; reading paths.yaml and writing files live in
 * the policy tool.
 *
 * <p>Each route's proof is handed only to its second-to-last hop (the caller
 * that attaches it, held by its service when the hop is {@code <service>#<operation>}),
 * so a service with no legitimate route to a destination is never given a proof for one.
 * Salts are freshly random each run. Routes go in random distinct slots, so a proof's
 * {@code dirs} does not reveal the route's
 * position in the policy (a lower bound on the route count). The {@code rootId}
 * is a random label per build, not derived from the routes, so it cannot be used
 * to confirm a guess at the policy's content.
 *
 * <p>A route of two nodes whose last is {@code ops:<hash>} covers a service's operation table. Its proof goes to
 * the service and to every holder of a route that ends at the service, since those callers must check the table
 * they use. It has no bundle of its own for the {@code ops:} node.
 */
public final class PolicyBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SALT_BYTES = MerkleProof.SALT_BYTES;

    private PolicyBuilder() {
    }

    public record Result(SignedRoot signedRoot, Map<String, ProofBundle> bundles) {
    }

    /**
     * Builds the tree and signs its root, vouched for until {@code notAfter} (milliseconds since the epoch,
     * inclusive). The caller must currently allow every route in {@code routes}: the signature says so until
     * {@code notAfter}, and nothing can take it back sooner. Throws {@link IllegalArgumentException}, signing
     * nothing, for a node {@link Routes#requireValidNode} refuses.
     */
    public static Result build(List<List<String>> routes, int depth, long notAfter, PrivateKey policyKey) {
        for (List<String> route : routes) {
            for (int i = 0; i < route.size(); i++) {
                requireValidNodeAt(route.get(i), i == route.size() - 1);
            }
        }
        List<String> routeStrings = routes.stream().map(r -> Routes.join(r)).toList();
        String rootId = newRootId();

        List<MerkleLeaf> leaves = routeStrings.stream()
                .map(route -> new MerkleLeaf(Crypto.randomBytes(SALT_BYTES), route))
                .toList();
        MerkleTree tree = MerkleTree.build(leaves, depth, rootId, randomSlots(leaves.size(), depth));
        SignedRoot signedRoot = SignedRoot.sign(tree.root(), rootId, notAfter, policyKey);

        // Every service that appears anywhere gets a bundle, empty by default.
        Map<String, Map<String, MerkleProof>> proofsByService = new LinkedHashMap<>();
        for (List<String> route : routes) {
            for (int i = 0; i < route.size(); i++) {
                if (i < route.size() - 1 || !isOpsNode(route.get(i))) {
                    proofsByService.computeIfAbsent(Routes.service(route.get(i)), k -> new LinkedHashMap<>());
                }
            }
        }

        for (int i = 0; i < routes.size(); i++) {
            List<String> route = routes.get(i);
            if (route.size() < 2) {
                throw new IllegalArgumentException("route has no caller (needs >= 2 nodes): " + route);
            }
            String proof = routeStrings.get(i);
            String holder = Routes.service(route.get(route.size() - 2)); // second-to-last hop
            proofsByService.get(holder).put(proof, tree.proofFor(proof));
            if (route.size() == 2 && isOpsNode(route.get(1))) {
                // An operation table's callers need its proof too: every holder of a route that ends at the service.
                for (int j = 0; j < routes.size(); j++) {
                    List<String> other = routes.get(j);
                    if (other.size() >= 2 && Routes.service(other.get(other.size() - 1)).equals(route.get(0))) {
                        String caller = Routes.service(other.get(other.size() - 2));
                        proofsByService.get(caller).put(proof, tree.proofFor(proof));
                    }
                }
            }
        }

        Map<String, ProofBundle> bundles = new LinkedHashMap<>();
        proofsByService.forEach((svc, proofs) -> bundles.put(svc, new ProofBundle(svc, rootId, proofs)));
        return new Result(signedRoot, bundles);
    }

    private static boolean isOpsNode(String node) {
        return node.startsWith("ops:");
    }

    /** A node before the last is a service or {@code <service>#<operation>}; the last is any valid node. */
    private static void requireValidNodeAt(String node, boolean last) {
        if (last) {
            Routes.requireValidNode(node);
            return;
        }
        Routes.requireValidService(Routes.service(node));
        int hash = node.indexOf('#');
        if (hash >= 0) {
            Routes.requireValidOperation(node.substring(hash + 1));
        }
    }

    /** {@code "v"} plus 12 lowercase hex characters from a CSPRNG. */
    static String newRootId() {
        return "v" + HexFormat.of().formatHex(Crypto.randomBytes(6));
    }

    /** The first {@code n} of a uniform shuffle of all {@code 2^depth} slots. */
    private static int[] randomSlots(int n, int depth) {
        int total = 1 << depth;
        if (n > total) {
            throw new IllegalArgumentException("depth " + depth + " holds " + total + " leaves, got " + n);
        }
        int[] all = new int[total];
        for (int i = 0; i < total; i++) {
            all[i] = i;
        }
        for (int i = total - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            int t = all[i];
            all[i] = all[j];
            all[j] = t;
        }
        return java.util.Arrays.copyOf(all, n);
    }
}
