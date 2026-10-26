// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

class PolicyToolMainTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String PATHS_YAML = """
            paths:
              - [gateway, orders, payment]
              - [gateway, orders]
              - [gateway, search]
            """;

    private KeyPair writeWorld(Path keys, Path pathsYaml) throws Exception {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        Files.createDirectories(keys);
        Files.writeString(keys.resolve("policy.key"), Base64Url.encode(Crypto.encodePrivateKey(policy.getPrivate())));
        Files.writeString(pathsYaml, PATHS_YAML);
        return policy;
    }

    @Test
    void writesSignedRootAndOneBundlePerService(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);

        PolicyToolMain.run(pathsYaml, keys, out, 8);

        assertTrue(Files.exists(out.resolve("root.json")));
        for (String svc : new String[] {"gateway", "orders", "payment", "search"}) {
            assertTrue(Files.exists(out.resolve("proofs-" + svc + ".json")), "missing bundle for " + svc);
        }
    }

    @Test
    void rootJsonVerifiesAgainstThePolicyKey(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);

        PolicyToolMain.run(pathsYaml, keys, out, 8);

        SignedRoot root = JSON.readValue(Files.readAllBytes(out.resolve("root.json")), SignedRoot.class);
        assertTrue(root.verify(policy.getPublic()));
    }

    @Test
    void searchBundleIsEmptyAndOrdersProofVerifies(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);

        PolicyToolMain.run(pathsYaml, keys, out, 8);

        ProofBundle search = JSON.readValue(Files.readAllBytes(out.resolve("proofs-search.json")), ProofBundle.class);
        assertTrue(search.proofs().isEmpty(), "search must hold no proofs");

        SignedRoot root = JSON.readValue(Files.readAllBytes(out.resolve("root.json")), SignedRoot.class);
        ProofBundle orders = JSON.readValue(Files.readAllBytes(out.resolve("proofs-orders.json")), ProofBundle.class);
        assertFalse(orders.proofs().isEmpty());
        assertTrue(orders.proofs().get("gateway/orders/payment").verify("gateway/orders/payment", root.rootBytes()));
    }
}
