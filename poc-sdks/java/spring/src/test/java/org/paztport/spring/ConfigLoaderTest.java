// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.MerkleLeaf;
import org.paztport.core.MerkleTree;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

class ConfigLoaderTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    @Test
    void loadsPrivateKeyKeyringPolicyKeyRootAndBundleFromFiles(@TempDir Path dir) throws Exception {
        // Write a world shaped exactly like keygen/policy-tool output.
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));

        KeyringFile keyring = new KeyringFile(
                Map.of("gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic()))),
                Base64Url.encode(Crypto.encodePublicKey(policy.getPublic())));
        JSON.writeValue(dir.resolve("keyring.json").toFile(), keyring);

        MerkleTree tree = MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")), 8, "v1");
        SignedRoot signedRoot = SignedRoot.sign(tree.root(), "v1", policy.getPrivate());
        JSON.writeValue(dir.resolve("root.json").toFile(), signedRoot);

        ProofBundle bundle = new ProofBundle("gateway", "v1", Map.of("gateway/orders", tree.proofFor("gateway/orders")));
        JSON.writeValue(dir.resolve("proofs-gateway.json").toFile(), bundle);

        // Load them back.
        var priv = ConfigLoader.loadPrivateKey(dir.resolve("gateway.key"));
        var loadedKeyring = ConfigLoader.loadKeyring(dir.resolve("keyring.json"));
        var policyKey = ConfigLoader.loadPolicyKey(dir.resolve("keyring.json"));
        var loadedRoot = ConfigLoader.loadSignedRoot(dir.resolve("root.json"));
        var loadedBundle = ConfigLoader.loadProofBundle(dir.resolve("proofs-gateway.json"));

        byte[] msg = "x".getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(loadedKeyring.keyFor("gateway"), msg, Crypto.sign(priv, msg)));
        assertTrue(loadedRoot.verify(policyKey), "root must verify against the loaded policy key");
        assertNotNull(loadedBundle.proofFor("gateway/orders"));
    }
}
