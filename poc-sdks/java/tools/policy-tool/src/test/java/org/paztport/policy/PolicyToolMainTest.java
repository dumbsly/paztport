// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;

class PolicyToolMainTest {

    /** The fixture keyring's validity window: 2100-01-01, beyond any clock here. */
    private static final long KEYRING_NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String PATHS_YAML = """
            paths:
              - [gateway, orders, payment]
              - [gateway, orders]
              - [gateway, search]
            """;

    /** Writes the policy key, a keyring it signed, and the paths file: what a rebuild reads. */
    private KeyPair writeWorld(Path keys, Path pathsYaml) throws Exception {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        Files.createDirectories(keys);
        Files.writeString(keys.resolve("policy.key"), Base64Url.encode(Crypto.encodePrivateKey(policy.getPrivate())));
        writeKeyring(keys, policy, policy);
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

        SignedRoot root = SignedRoot.load(out.resolve("root.json"));
        assertTrue(root.verify(policy.getPublic()));
    }

    /** The root is signed vouching for its routes for seven days from the run. */
    @Test
    void rootJsonIsSignedForSevenDays(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);

        long before = System.currentTimeMillis();
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        long after = System.currentTimeMillis();

        SignedRoot root = SignedRoot.load(out.resolve("root.json"));
        assertTrue(root.notAfter() >= before + 7 * DAY_MS && root.notAfter() <= after + 7 * DAY_MS,
                String.valueOf(root.notAfter()));
        assertTrue(root.verify(policy.getPublic()));
    }

    @Test
    void searchBundleIsEmptyAndOrdersProofVerifies(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);

        PolicyToolMain.run(pathsYaml, keys, out, 8);

        ProofBundle search = ProofBundle.load(out.resolve("proofs-search.json"));
        assertTrue(search.proofs().isEmpty(), "search must hold no proofs");

        SignedRoot root = SignedRoot.load(out.resolve("root.json"));
        ProofBundle orders = ProofBundle.load(out.resolve("proofs-orders.json"));
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
                pub(policy), KEYRING_NOT_AFTER, signer.getPrivate());
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
    void filesAreInTheFileFormat(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);

        PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER);
        assertInTheFileFormat(keys.resolve("keyring.json"), out.resolve("root.json"), out.resolve("reply-cert.json"),
                out.resolve("proofs-gateway.json"), out.resolve("proofs-orders.json"));

        PolicyToolMain.renew(keys, out, NOT_AFTER, "orders", NOT_AFTER);
        assertInTheFileFormat(keys.resolve("keyring.json"), out.resolve("root.json"), out.resolve("reply-cert.json"));
    }

    private static void assertInTheFileFormat(Path... files) throws IOException {
        for (Path f : files) {
            byte[] bytes = Files.readAllBytes(f);
            assertEquals(new String(bytes, StandardCharsets.UTF_8), JsonWriter.file(JsonReader.file(bytes)),
                    f.toString());
        }
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
        KeyringFile signed = KeyringFile.load(keys.resolve("keyring.json"));
        KeyringFile tampered = new KeyringFile(Map.of("orders", pub(Crypto.generateEd25519KeyPair())),
                signed.policy(), signed.sig(), signed.notAfter());
        JSON.writeValue(keys.resolve("keyring.json").toFile(), tampered);

        assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
        assertFalse(Files.exists(out));

        JSON.writeValue(keys.resolve("keyring.json").toFile(),
                new KeyringFile(signed.services(), signed.policy(), null, signed.notAfter()));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
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

        assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
        assertFalse(Files.exists(out));
    }

    @Test
    void refusesARouteNodeCoreRefusesAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        for (String bad : new String[] {"\"..\"", "\"a|b\"", "\"a\\\\b\"", "\"\"", "\"a/b\""}) {
            Files.writeString(pathsYaml, "paths:\n  - [gateway, " + bad + "]\n");
            Map<Path, String> before = snapshot(keys);

            assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8), bad);
            assertFalse(Files.exists(out), bad);
            assertEquals(before, snapshot(keys), bad);
        }
    }

    @Test
    void refusesAServiceTheKeyringLacksAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        writeKeyring(keys, policy, policy);

        assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "payment", NOT_AFTER));
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

    /** Every file under {@code dirs}, by path, as its bytes and modification time: what "writes nothing" compares. */
    private static Map<Path, String> snapshot(Path... dirs) throws Exception {
        Map<Path, String> files = new TreeMap<>();
        for (Path d : dirs) {
            if (!Files.exists(d)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(d)) {
                for (Path f : walk.filter(Files::isRegularFile).toList()) {
                    files.put(f,
                            Base64Url.encode(Files.readAllBytes(f)) + "@" + Files.getLastModifiedTime(f).toMillis());
                }
            }
        }
        return files;
    }

    /** A rebuild signs a new root and re-signs the keyring, both until the one {@code notAfter} it is given. */
    @Test
    void rebuildSignsRootAndKeyringWithLifetime(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        KeyringFile before = KeyringFile.load(keys.resolve("keyring.json"));
        long notAfter = PolicyToolMain.policyNotAfter("30", System.currentTimeMillis());

        PolicyToolMain.run(pathsYaml, keys, out, 8, notAfter, null, 0);

        SignedRoot root = SignedRoot.load(out.resolve("root.json"));
        assertEquals(notAfter, root.notAfter());
        assertTrue(root.verify(policy.getPublic()));
        KeyringFile ring = KeyringFile.load(keys.resolve("keyring.json"));
        assertEquals(notAfter, ring.notAfter());
        assertTrue(ring.verifies(pub(policy)));
        assertEquals(before.services(), ring.services());
        assertEquals(before.policy(), ring.policy());
    }

    @Test
    void policyLifetimeIsDaysFromNowDefaultSeven() {
        assertEquals(1000 + 7 * DAY_MS, PolicyToolMain.policyNotAfter(null, 1000));
        assertEquals(1000 + 30 * DAY_MS, PolicyToolMain.policyNotAfter("30", 1000));
        // Days whose end would pass 2^53 - 1 ms are refused, not signed; so for certificates.
        for (String bad : new String[] {"0", "-1", "x", "", "1.5", "200000000"}) {
            assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.policyNotAfter(bad, 1000), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.replyCertNotAfter("200000000", 1000));
    }

    /** A rebuild refuses, writing nothing, a keyring that is missing, unsound, or another policy key's. */
    @Test
    void rebuildRefusesForeignKeyring(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        KeyPair other = Crypto.generateEd25519KeyPair();
        writeKeyring(keys, other, other);
        Map<Path, String> before = snapshot(keys);

        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8));
        assertEquals(before, snapshot(keys));
        assertFalse(Files.exists(out));

        // Signed by this policy key, but naming another: it does not verify under the key it names.
        KeyPair policy = Crypto.generateEd25519KeyPair();
        Files.writeString(keys.resolve("policy.key"), Base64Url.encode(Crypto.encodePrivateKey(policy.getPrivate())));
        writeKeyring(keys, other, policy);
        before = snapshot(keys);
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8));
        assertEquals(before, snapshot(keys));
        assertFalse(Files.exists(out));

        Files.delete(keys.resolve("keyring.json"));
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.run(pathsYaml, keys, out, 8));
        assertFalse(Files.exists(keys.resolve("keyring.json")));
        assertFalse(Files.exists(out));
    }

    /**
     * Renewal signs the same tree again: {@code rootId} and {@code root} are kept, so the bundles already held still
     * prove against the renewed root, untouched; the keyring and the reply certificate are renewed beside it.
     */
    @Test
    void renewKeepsTreeAndProofs(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        long now = System.currentTimeMillis();
        PolicyToolMain.run(pathsYaml, keys, out, 8, now + DAY_MS, null, 0);
        SignedRoot built = SignedRoot.load(out.resolve("root.json"));
        KeyringFile ringBefore = KeyringFile.load(keys.resolve("keyring.json"));
        Map<Path, String> bundles = new TreeMap<>(snapshot(out));
        bundles.remove(out.resolve("root.json"));
        // Renewal reads neither the paths file nor anything but root.json from the output: a narrowed one is ignored.
        Files.writeString(pathsYaml, "paths:\n  - [gateway, search]\n");

        long later = now + 30 * DAY_MS;
        PolicyToolMain.renew(keys, out, later, "orders", NOT_AFTER);

        SignedRoot renewed = SignedRoot.load(out.resolve("root.json"));
        assertEquals(built.rootId(), renewed.rootId());
        assertEquals(built.root(), renewed.root());
        assertEquals(later, renewed.notAfter());
        assertTrue(renewed.notAfter() > built.notAfter());
        assertTrue(renewed.verify(policy.getPublic()));
        Map<Path, String> after = new TreeMap<>(snapshot(out));
        after.remove(out.resolve("root.json"));
        after.remove(out.resolve("reply-cert.json"));
        assertEquals(bundles, after);
        ProofBundle orders = ProofBundle.load(out.resolve("proofs-orders.json"));
        assertEquals(renewed.rootId(), orders.rootId());
        assertTrue(orders.proofs().get("gateway/orders/payment").verify("gateway/orders/payment", renewed.rootBytes()));

        KeyringFile ring = KeyringFile.load(keys.resolve("keyring.json"));
        assertEquals(later, ring.notAfter());
        assertEquals(ringBefore.services(), ring.services());
        assertTrue(ring.verifies(pub(policy)));
        ReplyCert cert = ReplyCert.load(out.resolve("reply-cert.json"));
        assertTrue(cert.verifies(pub(policy)));
        assertEquals(ring.services().get("orders"), cert.key());
        assertEquals(NOT_AFTER, cert.notAfter());
    }

    /** A root another policy key signed is not renewed, and nothing is written, the keyring included. */
    @Test
    void renewRefusesForeignRoot(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        SignedRoot built = SignedRoot.load(out.resolve("root.json"));
        KeyPair other = Crypto.generateEd25519KeyPair();
        JSON.writeValue(out.resolve("root.json").toFile(),
                SignedRoot.sign(built.rootBytes(), built.rootId(), KEYRING_NOT_AFTER, other.getPrivate()));
        Map<Path, String> before = snapshot(keys, out);

        assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, "orders", NOT_AFTER));
        assertEquals(before, snapshot(keys, out));

        // A tampered root, and a missing one, are refused alike.
        JSON.writeValue(out.resolve("root.json").toFile(),
                new SignedRoot(built.rootId(), built.root(), built.sig(), built.notAfter() + 1));
        before = snapshot(keys, out);
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(before, snapshot(keys, out));
        Files.delete(out.resolve("root.json"));
        before = snapshot(keys, out);
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(before, snapshot(keys, out));
    }

    /** A keyring another policy key signed, or one tampered with, is not renewed, and nothing is written. */
    @Test
    void renewRefusesForeignKeyring(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        KeyringFile signed = KeyringFile.load(keys.resolve("keyring.json"));
        KeyPair other = Crypto.generateEd25519KeyPair();
        writeKeyring(keys, other, other);
        Map<Path, String> before = snapshot(keys, out);

        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(before, snapshot(keys, out));

        JSON.writeValue(keys.resolve("keyring.json").toFile(), new KeyringFile(
                Map.of("orders", pub(other)), signed.policy(), signed.sig(), signed.notAfter()));
        before = snapshot(keys, out);
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(before, snapshot(keys, out));
    }

    /** Lapsed material is renewed all the same: renewal is how it comes back. */
    @Test
    void renewAcceptsExpired(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        SignedRoot built = SignedRoot.load(out.resolve("root.json"));
        KeyringFile ring = KeyringFile.load(keys.resolve("keyring.json"));
        long later = System.currentTimeMillis() + 30 * DAY_MS;

        JSON.writeValue(out.resolve("root.json").toFile(), built.renewed(1000, policy.getPrivate()));
        JSON.writeValue(keys.resolve("keyring.json").toFile(), ring.renewed(1000, policy.getPrivate()));
        PolicyToolMain.renew(keys, out, later, null, 0);
        assertRenewed(keys, out, built, policy, later);
    }

    /**
     * A root or keyring without {@code notAfter} is malformed, so it is refused (the tool exits 2) and nothing is
     * written, though its signature is the policy key's over the same fields without a window.
     */
    @Test
    void renewRefusesMaterialWithoutNotAfterAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        KeyPair policy = writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        SignedRoot built = SignedRoot.load(out.resolve("root.json"));
        KeyringFile ring = KeyringFile.load(keys.resolve("keyring.json"));
        String rootFile = Files.readString(out.resolve("root.json"));

        Files.writeString(out.resolve("root.json"), "{\"rootId\":\"" + built.rootId() + "\",\"root\":\""
                + built.root() + "\",\"sig\":\"" + sign(policy, built.rootId() + "|" + built.root()) + "\"}");
        Map<Path, String> before = snapshot(keys, out);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(out.resolve("root.json") + " is missing or not a signed root: no member notAfter", e.getMessage());
        assertEquals(before, snapshot(keys, out));

        Files.writeString(out.resolve("root.json"), rootFile);
        String services = JSON.writeValueAsString(new TreeMap<>(ring.services()));
        String body = "{\"policy\":\"" + ring.policy() + "\",\"services\":" + services + "}";
        Files.writeString(keys.resolve("keyring.json"), "{\"services\":" + services + ",\"policy\":\"" + ring.policy()
                + "\",\"sig\":\"" + sign(policy, "paztport-keyring\n" + body) + "\"}");
        before = snapshot(keys, out);
        e = assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(keys.resolve("keyring.json") + " is missing or not a keyring: no member notAfter",
                e.getMessage());
        assertEquals(before, snapshot(keys, out));
    }

    /** A {@code notAfter} is a protocol integer by its text, so one written with a fraction is refused, as above. */
    @Test
    void renewRefusesANotAfterWrittenWithAFractionAndWritesNothing(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        String keyring = Files.readString(keys.resolve("keyring.json"));
        Files.writeString(keys.resolve("keyring.json"), keyring.replaceFirst("(\"notAfter\": [0-9]+)", "$1.0"));
        Map<Path, String> before = snapshot(keys, out);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, null, 0));
        assertEquals(keys.resolve("keyring.json") + " is missing or not a keyring: "
                + "JSON refused: a number that is not an integer, at byte 29", e.getMessage());
        assertEquals(before, snapshot(keys, out));
    }

    private static String sign(KeyPair policy, String text) {
        return Base64Url.encode(Crypto.sign(policy.getPrivate(), text.getBytes(StandardCharsets.UTF_8)));
    }

    private static void assertRenewed(Path keys, Path out, SignedRoot built, KeyPair policy, long notAfter) {
        SignedRoot root = SignedRoot.load(out.resolve("root.json"));
        assertTrue(root.isCurrent(System.currentTimeMillis()));
        assertEquals(notAfter, root.notAfter());
        assertEquals(built.rootId(), root.rootId());
        assertEquals(built.root(), root.root());
        assertTrue(root.verify(policy.getPublic()));
        KeyringFile ring = KeyringFile.load(keys.resolve("keyring.json"));
        assertTrue(ring.isCurrent(System.currentTimeMillis()));
        assertEquals(notAfter, ring.notAfter());
        assertTrue(ring.verifies(pub(policy)));
    }

    /** Renewal is asked for by {@code --renew} anywhere on the line or by {@code PAZTPORT_RENEW=true}. */
    @Test
    void renewIsAnArgumentOrTheEnvironment() {
        PolicyToolMain.Args rebuild = PolicyToolMain.parse(new String[] {"p.yaml", "k", "o"}, null);
        assertFalse(rebuild.renew());
        assertEquals(Path.of("p.yaml"), rebuild.pathsYaml());
        assertEquals(Path.of("k"), rebuild.keysDir());
        assertEquals(Path.of("o"), rebuild.outDir());
        assertFalse(PolicyToolMain.parse(new String[] {}, "false").renew());
        assertFalse(PolicyToolMain.parse(new String[] {}, "").renew());
        assertEquals(Path.of("out/keys"), PolicyToolMain.parse(new String[] {}, null).keysDir());

        PolicyToolMain.Args renew = PolicyToolMain.parse(new String[] {"p.yaml", "--renew", "k", "o"}, null);
        assertTrue(renew.renew());
        assertEquals(Path.of("k"), renew.keysDir());
        assertEquals(Path.of("o"), renew.outDir());
        assertTrue(PolicyToolMain.parse(new String[] {"p.yaml", "k", "o"}, "true").renew());
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.parse(new String[] {}, "yes"));
        assertThrows(IllegalArgumentException.class, () -> PolicyToolMain.parse(new String[] {"--rebuild"}, null));
    }

    /**
     * A keyring the tool cannot write (as when it is mounted read-only) stops either mode with one named line, not a
     * stack trace, and since the keyring is the first write, nothing at all is written.
     */
    @Test
    void anUnwritableKeyringIsNamedAndNothingIsWritten(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path pathsYaml = dir.resolve("paths.yaml");
        Path out = dir.resolve("out");
        writeWorld(keys, pathsYaml);
        PolicyToolMain.run(pathsYaml, keys, out, 8);
        Path keyring = keys.resolve("keyring.json");
        assertTrue(keyring.toFile().setWritable(false));
        try {
            assumeFalse(Files.isWritable(keyring), "running as a user who can write a read-only file");
            Map<Path, String> before = snapshot(keys, out);

            PolicyToolMain.CannotWrite rebuild = assertThrows(PolicyToolMain.CannotWrite.class,
                    () -> PolicyToolMain.run(pathsYaml, keys, out, 8, "orders", NOT_AFTER));
            assertEquals("cannot write " + keyring + ": Permission denied", rebuild.getMessage());
            assertEquals(before, snapshot(keys, out));

            PolicyToolMain.CannotWrite renew = assertThrows(PolicyToolMain.CannotWrite.class,
                    () -> PolicyToolMain.renew(keys, out, KEYRING_NOT_AFTER, "orders", NOT_AFTER));
            assertEquals("cannot write " + keyring + ": Permission denied", renew.getMessage());
            assertEquals(before, snapshot(keys, out));
        } finally {
            keyring.toFile().setWritable(true);
        }
    }

    /** The one line names the cause the file system gave, rather than guessing at it. */
    @Test
    void cannotWriteSaysWhy() {
        Path file = Path.of("keys", "keyring.json");
        assertEquals("cannot write " + file + ": Read-only file system", new PolicyToolMain.CannotWrite(file,
                new FileSystemException(file.toString(), null, "Read-only file system")).getMessage());
        assertEquals("cannot write " + file + ": No space left on device",
                new PolicyToolMain.CannotWrite(file, new IOException("No space left on device")).getMessage());
        assertEquals("cannot write " + file + ": Permission denied",
                new PolicyToolMain.CannotWrite(file, new AccessDeniedException(file.toString())).getMessage());
        assertEquals("cannot write " + file + ": No such file or directory",
                new PolicyToolMain.CannotWrite(file, new NoSuchFileException(file.toString())).getMessage());
        assertEquals("cannot write " + file + ": FileSystemException",
                new PolicyToolMain.CannotWrite(file, new FileSystemException(file.toString())).getMessage());
    }
}
