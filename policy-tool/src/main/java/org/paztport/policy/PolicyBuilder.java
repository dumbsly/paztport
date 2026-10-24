// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import java.security.PrivateKey;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.Crypto;
import org.paztport.core.MerkleLeaf;
import org.paztport.core.MerkleProof;
import org.paztport.core.MerkleTree;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

/**
 * Turns a list of allowed routes into a signed Merkle root and per-service proof
 * bundles. Pure logic; reading paths.yaml and writing files live in
 * {@link PolicyToolMain}.
 *
 * <p>Each route's proof is handed only to its second-to-last hop (the caller
 * that attaches it), so a service with no legitimate route to a destination is
 * never given a proof for one. Salts are freshly random each run; the
 * {@code rootId} is derived from the policy content, so it is a stable label for
 * a given set of routes even as the root bytes change.
 */
public final class PolicyBuilder {

    private static final int SALT_BYTES = 16;

    private PolicyBuilder() {
    }

    public record Result(SignedRoot signedRoot, Map<String, ProofBundle> bundles) {
    }

    public static Result build(List<List<String>> routes, int depth, PrivateKey policyKey) {
        List<String> routeStrings = routes.stream().map(r -> String.join("/", r)).toList();
        String rootId = deriveRootId(routeStrings);

        List<MerkleLeaf> leaves = routeStrings.stream()
                .map(route -> new MerkleLeaf(Crypto.randomBytes(SALT_BYTES), route))
                .toList();
        MerkleTree tree = MerkleTree.build(leaves, depth, rootId);
        SignedRoot signedRoot = SignedRoot.sign(tree.root(), rootId, policyKey);

        // Every service that appears anywhere gets a bundle, empty by default.
        Map<String, Map<String, MerkleProof>> proofsByService = new LinkedHashMap<>();
        for (List<String> route : routes) {
            for (String node : route) {
                proofsByService.computeIfAbsent(node, k -> new LinkedHashMap<>());
            }
        }

        for (int i = 0; i < routes.size(); i++) {
            List<String> route = routes.get(i);
            if (route.size() < 2) {
                throw new IllegalArgumentException("route has no caller (needs >= 2 nodes): " + route);
            }
            String holder = route.get(route.size() - 2); // second-to-last hop
            proofsByService.get(holder).put(routeStrings.get(i), tree.proofFor(routeStrings.get(i)));
        }

        Map<String, ProofBundle> bundles = new LinkedHashMap<>();
        proofsByService.forEach((svc, proofs) -> bundles.put(svc, new ProofBundle(svc, rootId, proofs)));
        return new Result(signedRoot, bundles);
    }

    /** {@code "v" + first 12 hex of SHA-256(routes joined by newline, in file order)}. */
    private static String deriveRootId(List<String> routeStrings) {
        byte[] digest = Crypto.sha256(String.join("\n", routeStrings).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "v" + HexFormat.of().formatHex(digest).substring(0, 12);
    }
}
