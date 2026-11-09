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
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonWriter;

class ToolOutputFilesTest {

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
        Files.writeString(dir.resolve("keyring.json"), keyring.toFile());

        MerkleTree tree = MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")), 8, "v1");
        SignedRoot signedRoot = SignedRoot.sign(tree.root(), "v1", NOT_AFTER, policy.getPrivate());
        Files.writeString(dir.resolve("root.json"), signedRoot.toFile());

        ProofBundle bundle =
                new ProofBundle("gateway", "v1", Map.of("gateway/orders", tree.proofFor("gateway/orders")));
        Files.writeString(dir.resolve("proofs-gateway.json"), bundle.toFile());

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

    /** A root or keyring whose {@code notAfter} is not a protocol integer is refused at startup, never truncated. */
    @Test
    void refusesANotAfterThatIsNotAnInteger(@TempDir Path dir) throws Exception {
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        SignedRoot root = SignedRoot.sign(Crypto.sha256("r".getBytes()), "v1", 1_798_761_600_000L, policy.getPrivate());
        ObjectNode rootJson = (ObjectNode) JSON.readTree(root.toJson());
        rootJson.put("notAfter", 1.5);
        JSON.writeValue(dir.resolve("root.json").toFile(), rootJson);
        KeyringFile ring = KeyringFile.sign(Map.of("gateway", policyPub), policyPub, 1_798_761_600_000L,
                policy.getPrivate());
        ObjectNode ringJson = (ObjectNode) JSON.readTree(ring.toJson());
        ringJson.put("notAfter", 1.5);
        JSON.writeValue(dir.resolve("keyring.json").toFile(), ringJson);

        assertThrows(IllegalArgumentException.class, () -> SignedRoot.load(dir.resolve("root.json")));
        assertThrows(IllegalArgumentException.class, () -> KeyringFile.load(dir.resolve("keyring.json")));
    }

    /**
     * A bundle is read as a file, in any member order and spacing, and strictly: a member it does not define, a name
     * in {@code proofs} that is not a route, and a proof its schema refuses are each refused, naming no route.
     */
    @Test
    void aProofBundleIsReadStrictly(@TempDir Path dir) throws Exception {
        MerkleTree tree = MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")), 8, "v1");
        MerkleProof proof = tree.proofFor("gateway/orders");
        ProofBundle bundle = new ProofBundle("gateway", "v1", Map.of("gateway/orders", proof));
        Path file = dir.resolve("proofs-gateway.json");
        JSON.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), bundle);
        assertEquals(bundle, ProofBundle.load(file));

        ObjectNode extra = (ObjectNode) JSON.readTree(bundle.toFile());
        extra.put("note", "x");
        JSON.writeValue(file.toFile(), extra);
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> ProofBundle.load(file)).getMessage());

        for (String route : List.of("gateway", "gateway/", "/orders", "gateway//orders", "gateway/../orders")) {
            JSON.writeValue(file.toFile(), new ProofBundle("gateway", "v1", Map.of(route, proof)));
            assertEquals("member proofs holds a name that is not a route",
                    assertThrows(IllegalArgumentException.class, () -> ProofBundle.load(file), route).getMessage());
        }

        ObjectNode bad = (ObjectNode) JSON.readTree(bundle.toFile());
        ((ObjectNode) bad.get("proofs").get("gateway/orders")).put("extra", 1);
        JSON.writeValue(file.toFile(), bad);
        assertEquals("a member the object does not define",
                assertThrows(IllegalArgumentException.class, () -> ProofBundle.load(file)).getMessage());
    }

    /** A bundle is only a file, so one over the wire limit and under the file limit is written and read back. */
    @Test
    void aProofBundleOverTheWireLimitIsWrittenAsAFile(@TempDir Path dir) throws Exception {
        List<MerkleLeaf> leaves = new java.util.ArrayList<>();
        Map<String, MerkleProof> proofs = new java.util.TreeMap<>();
        for (int i = 0; i < 600; i++) {
            leaves.add(new MerkleLeaf(Crypto.randomBytes(16), "hub/svc" + i));
        }
        MerkleTree tree = MerkleTree.build(leaves, 10, "v1");
        leaves.forEach(l -> proofs.put(l.path(), tree.proofFor(l.path())));
        ProofBundle bundle = new ProofBundle("hub", "v1", proofs);

        String file = bundle.toFile();
        int bytes = file.getBytes(StandardCharsets.UTF_8).length;
        assertTrue(bytes > JsonReader.WIRE_BYTES && bytes < JsonReader.FILE_BYTES, "size " + bytes);
        Files.writeString(dir.resolve("proofs-hub.json"), file);
        assertEquals(file, JsonWriter.file(JsonReader.file(file.getBytes(StandardCharsets.UTF_8))));
        assertEquals(bundle, ProofBundle.load(dir.resolve("proofs-hub.json")));
    }
}
