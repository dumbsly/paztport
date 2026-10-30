// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.encoding.Base64Url;

class ConfigFilesTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    @Test
    void loadsPrivateKeyKeyringPolicyPinRootAndBundleFromFiles(@TempDir Path dir) throws Exception {
        // Write a world shaped exactly like keygen/policy-tool output.
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));

        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Files.writeString(dir.resolve("policy.pub"), "  " + policyPub + "\n");
        KeyringFile keyring = KeyringFile.sign(
                Map.of("gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic()))),
                policyPub, NOT_AFTER, policy.getPrivate());
        JSON.writeValue(dir.resolve("keyring.json").toFile(), keyring);

        MerkleTree tree = MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")), 8, "v1");
        SignedRoot signedRoot = SignedRoot.sign(tree.root(), "v1", NOT_AFTER, policy.getPrivate());
        JSON.writeValue(dir.resolve("root.json").toFile(), signedRoot);

        ProofBundle bundle = new ProofBundle("gateway", "v1", Map.of("gateway/orders", tree.proofFor("gateway/orders")));
        JSON.writeValue(dir.resolve("proofs-gateway.json").toFile(), bundle);

        // Load them back.
        var priv = KeyFiles.loadPrivateKey(dir.resolve("gateway.key"));
        var loadedKeyring = KeyringFile.load(dir.resolve("keyring.json"));
        var pin = KeyFiles.loadPolicyPin(dir.resolve("policy.pub"));
        var loadedRoot = SignedRoot.load(dir.resolve("root.json"));
        var loadedBundle = ProofBundle.load(dir.resolve("proofs-gateway.json"));

        byte[] msg = "x".getBytes(StandardCharsets.UTF_8);
        assertEquals(policyPub, pin, "the pin is the file's text, trimmed");
        assertTrue(loadedKeyring.verifies(pin), "the keyring must verify under the loaded pin");
        assertTrue(Crypto.verify(Keyring.fromFile(loadedKeyring).keyFor("gateway"), msg, Crypto.sign(priv, msg)));
        assertTrue(loadedRoot.verify(Crypto.decodePublicKey(Base64Url.decode(pin))),
                "root must verify against the pinned policy key");
        assertNotNull(loadedBundle.proofFor("gateway/orders"));
    }

    /**
     * A root or keyring whose {@code notAfter} is not an integer is refused at startup, not truncated: Jackson's
     * record binding would read {@code 1.5} as 1, which the TypeScript SDK refuses, so the two would disagree.
     */
    @Test
    void refusesANotAfterThatIsNotAnInteger(@TempDir Path dir) throws Exception {
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        SignedRoot root = SignedRoot.sign(Crypto.sha256("r".getBytes()), "v1", 1_798_761_600_000L, policy.getPrivate());
        ObjectNode rootJson = JSON.valueToTree(root);
        rootJson.put("notAfter", 1.5);
        JSON.writeValue(dir.resolve("root.json").toFile(), rootJson);
        KeyringFile ring = KeyringFile.sign(Map.of("gateway", policyPub), policyPub, 1_798_761_600_000L,
                policy.getPrivate());
        ObjectNode ringJson = JSON.valueToTree(ring);
        ringJson.put("notAfter", 1.5);
        JSON.writeValue(dir.resolve("keyring.json").toFile(), ringJson);

        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(dir.resolve("root.json")));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(dir.resolve("keyring.json")));
    }
}
