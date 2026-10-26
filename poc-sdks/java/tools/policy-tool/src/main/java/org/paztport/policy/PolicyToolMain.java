// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.List;
import org.paztport.core.KeyFiles;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

/**
 * CLI: build a signed root and per-service proof bundles from paths.yaml.
 *
 * <pre>policy-tool [paths.yaml] [keysDir] [outDir]</pre>
 *
 * Reads the policy private key from {@code keysDir/policy.key}. Depth comes from
 * {@code PAZTPORT_PROOF_DEPTH} (default 8). Only root id and service names are
 * logged, never salts or the tree.
 */
public final class PolicyToolMain {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private PolicyToolMain() {
    }

    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth) throws IOException {
        List<List<String>> routes = PathsReader.parse(Files.readAllBytes(pathsYaml));
        PrivateKey policyKey = KeyFiles.loadPrivateKey(keysDir.resolve("policy.key"));

        PolicyBuilder.Result result = PolicyBuilder.build(routes, depth, policyKey);

        Files.createDirectories(outDir);
        MAPPER.writeValue(outDir.resolve("root.json").toFile(), result.signedRoot());
        for (ProofBundle bundle : result.bundles().values()) {
            MAPPER.writeValue(outDir.resolve("proofs-" + bundle.service() + ".json").toFile(), bundle);
        }
    }

    public static void main(String[] args) throws IOException {
        Path pathsYaml = Path.of(args.length > 0 ? args[0] : "policy/paths.yaml");
        Path keysDir = Path.of(args.length > 1 ? args[1] : "out/keys");
        Path outDir = Path.of(args.length > 2 ? args[2] : "out/policy");
        int depth = Integer.parseInt(System.getenv().getOrDefault("PAZTPORT_PROOF_DEPTH", "8"));

        run(pathsYaml, keysDir, outDir, depth);

        SignedRoot root = new ObjectMapper().readValue(outDir.resolve("root.json").toFile(), SignedRoot.class);
        System.out.println("policy-tool: wrote root " + root.rootId() + " and per-service bundles to " + outDir);
    }
}
