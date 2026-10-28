// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.ProofBundle;
import org.paztport.core.ReplyCert;
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

    private static final long NOT_AFTER = 1_798_761_600_000L;
    private static final long DAY_MS = 86_400_000L;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** Writes keys/keyring.json naming orders' key, signed by {@code signer} and naming {@code policy}. */
    private static String writeKeyring(Path keys, KeyPair policy, KeyPair signer) throws Exception {
        String orders = pub(Crypto.generateEd25519KeyPair());
        KeyringFile ring = KeyringFile.sign(Map.of("gateway", pub(Crypto.generateEd25519KeyPair()), "orders", orders),
                pub(policy), signer.getPrivate());
        JSON.writeValue(keys.resolve("keyring.json").toFile(), ring);
        return orders;
    }

    @Test
    void writesAReplyCertForTheKeyringsKey(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        String orders = writeKeyring(keys, policy, policy);

        PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER);

        ReplyCert cert = ReplyCert.load(out.resolve("reply-cert.json"));
        assertTrue(cert.verifies(pub(policy)));
        assertEquals("orders", cert.svc());
        assertEquals(orders, cert.key());
        assertEquals(NOT_AFTER, cert.notAfter());
        assertTrue(Files.exists(out.resolve("root.json")));
    }

    @Test
    void noReplyCertUnlessAsked(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        writeKeyring(keys, policy, policy);

        PolicyToolMain.run(pathsYaml, keys, out, 8);

        assertFalse(Files.exists(out.resolve("reply-cert.json")));
    }

    @Test
    void refusesAKeyringThatDoesNotVerifyAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        writeKeyring(keys, policy, policy);
        KeyringFile signed = JSON.readValue(keys.resolve("keyring.json").toFile(), KeyringFile.class);
        KeyringFile tampered = new KeyringFile(Map.of("orders", pub(Crypto.generateEd25519KeyPair())),
                signed.policy(), signed.sig());
        JSON.writeValue(keys.resolve("keyring.json").toFile(), tampered);

        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
        assertFalse(Files.exists(out));

        JSON.writeValue(keys.resolve("keyring.json").toFile(), new KeyringFile(signed.services(), signed.policy(), null));
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
        assertFalse(Files.exists(out));
    }

    @Test
    void refusesAKeyringOfAnotherPolicyKeyAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        // A sound keyring, but of a policy key other than keys/policy.key.
        KeyPair other = Crypto.generateEd25519KeyPair();
        writeKeyring(keys, other, other);

        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
        assertFalse(Files.exists(out));
    }

    @Test
    void refusesAServiceTheKeyringLacksAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        writeKeyring(keys, policy, policy);

        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "payment", NOT_AFTER));
        assertFalse(Files.exists(out));
    }

    @Test
    void replyCertLifetimeIsDaysFromNowDefaultSeven() {
        assertEquals(1000 + 7 * DAY_MS, PolicyToolMain.replyCertNotAfter(null, 1000));
        assertEquals(1000 + 30 * DAY_MS, PolicyToolMain.replyCertNotAfter("30", 1000));
        for (String bad : new String[] {"0", "-1", "x", "", "1.5"}) {
            assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.replyCertNotAfter(bad, 1000), bad);
        }
    }
}
