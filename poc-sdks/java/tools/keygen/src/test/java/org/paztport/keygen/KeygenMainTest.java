// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;

class KeygenMainTest {

    private static final List<String> SERVICES = List.of("gateway", "orders", "payment", "search");
    private static final List<String> TLS_ONLY = List.of("operator", "responder");

    @Test
    void writesKeyringAndOnePrivateKeyFilePerServicePlusPolicy(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        assertTrue(Files.exists(dir.resolve("keyring.json")));
        assertTrue(Files.exists(dir.resolve("policy.key")));
        for (String svc : SERVICES) {
            assertTrue(Files.exists(dir.resolve(svc + ".key")), "missing private key for " + svc);
        }
    }

    @Test
    void keyringJsonParsesAndCoversEveryService(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = KeyringFile.load(dir.resolve("keyring.json"));
        for (String svc : SERVICES) {
            assertTrue(keyring.services().containsKey(svc));
        }
        assertTrue(keyring.policy() != null && !keyring.policy().isBlank());
    }

    @Test
    void writtenPrivateKeySignsWhatTheKeyringPublicKeyVerifies(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = KeyringFile.load(dir.resolve("keyring.json"));

        String privB64 = Files.readString(dir.resolve("gateway.key")).trim();
        var priv = Crypto.decodePrivateKey(Base64Url.decode(privB64));
        var pub = Crypto.decodePublicKey(Base64Url.decode(keyring.services().get("gateway")));

        byte[] msg = "hop".getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(pub, msg, Crypto.sign(priv, msg)));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void privateKeyFilesAreOwnerOnlyEvenWhenOverwritten(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");
        // A pre-existing, loosened key file must be tightened on re-run.
        Files.setPosixFilePermissions(dir.resolve("gateway.key"), PosixFilePermissions.fromString("rw-r--r--"));
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve("policy.key")));
        for (String svc : SERVICES) {
            assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve(svc + ".key")), svc);
        }
    }

    @Test
    void keyringIsSignedAndVerifiesUnderThePolicyPin(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = KeyringFile.load(dir.resolve("keyring.json"));
        String pin = Files.readString(dir.resolve("policy.pub")).trim();
        assertEquals(keyring.policy(), pin);
        assertTrue(keyring.verifies(pin));
        assertTrue(!keyring.verifies(Base64Url.encode(
                Crypto.encodePublicKey(Crypto.generateEd25519KeyPair().getPublic()))));
    }

    /**
     * The keyring is signed in the new form, vouching for its keys for seven days from the run unless
     * {@code PAZTPORT_POLICY_DAYS} says otherwise.
     */
    @Test
    void keygenWritesNewFormKeyring(@TempDir Path dir) throws Exception {
        long before = System.currentTimeMillis();
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");
        long after = System.currentTimeMillis();

        KeyringFile keyring = KeyringFile.load(dir.resolve("keyring.json"));
        assertTrue(keyring.isNewForm());
        assertTrue(keyring.notAfter() >= before + 7 * DAY_MS && keyring.notAfter() <= after + 7 * DAY_MS,
                String.valueOf(keyring.notAfter()));
        assertTrue(keyring.verifies(Files.readString(dir.resolve("policy.pub")).trim()));

        long thirtyDays = KeygenMain.keyringNotAfter("30", 1000);
        assertEquals(1000 + 30 * DAY_MS, thirtyDays);
        assertEquals(1000 + 7 * DAY_MS, KeygenMain.keyringNotAfter(null, 1000));
        Path other = dir.resolve("other");
        KeygenMain.run(other, SERVICES, TLS_ONLY, "shop", thirtyDays);
        KeyringFile set = KeyringFile.load(other.resolve("keyring.json"));
        assertEquals(thirtyDays, set.notAfter());
        assertTrue(set.verifies(Files.readString(other.resolve("policy.pub")).trim()));
        // Days whose end would pass 2^53 - 1 ms are refused, not signed.
        for (String bad : new String[] {"0", "-1", "x", "", "1.5", "200000000"}) {
            assertThrows(IllegalArgumentException.class, () -> KeygenMain.keyringNotAfter(bad, 1000), bad);
        }
    }

    private static final long DAY_MS = 86_400_000L;

    @Test
    void tlsOnlyNamesGetCertificatesButNeverEnterTheKeyring(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = KeyringFile.load(dir.resolve("keyring.json"));
        for (String name : TLS_ONLY) {
            assertTrue(!keyring.services().containsKey(name), name);
            assertTrue(!Files.exists(dir.resolve(name + ".key")), name + " has no stamp key");
        }
        for (String name : List.of("gateway", "orders", "payment", "search", "operator", "responder")) {
            assertTrue(Files.exists(dir.resolve("tls/" + name + ".crt")), name);
            assertTrue(Files.readString(dir.resolve("tls/" + name + ".key")).startsWith("-----BEGIN PRIVATE KEY-----"));
        }
        assertTrue(Files.exists(dir.resolve("tls/ca.crt")));
        assertTrue(!Files.exists(dir.resolve("tls/ca.key")), "the CA key must not sit in the mounted tls/ directory");
        assertTrue(Files.exists(dir.resolve("ca/ca.key")));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void tlsPrivateKeysAreOwnerOnlyIncludingTheCa(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        for (String name : List.of("gateway", "operator", "responder")) {
            assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve("tls/" + name + ".key")), name);
        }
        assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve("ca/ca.key")));
    }

    @Test
    void tlsOnlyMeansTheSameWhicheverSideOfOrgItIsOn() {
        assertEquals(List.of("operator", "responder"), KeygenMain.parse(new String[] {"out"}).tlsOnly());
        assertEquals(List.of(), KeygenMain.parse(new String[] {"out", "a", "--tls-only"}).tlsOnly());
        assertEquals(List.of(), KeygenMain.parse(new String[] {"out", "--org", "x", "a", "--tls-only"}).tlsOnly());
        assertEquals(List.of(), KeygenMain.parse(new String[] {"out", "a", "--tls-only", "--org", "x"}).tlsOnly());
        assertEquals(List.of("v"), KeygenMain.parse(new String[] {"out", "a", "--org", "x", "--tls-only", "v"}).tlsOnly());
        assertEquals(List.of("v"), KeygenMain.parse(new String[] {"out", "a", "--tls-only", "v", "--org", "x"}).tlsOnly());
        assertEquals("x", KeygenMain.parse(new String[] {"out", "a", "--tls-only", "v", "--org", "x"}).org());
    }

    @Test
    void refusesTheReservedNameDuplicatesAndNonLabels(@TempDir Path dir) {
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("ca"), List.of(), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("a"), List.of("ca"), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("a", "a"), List.of(), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("a"), List.of("a"), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("a,O=x"), List.of(), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("../a"), List.of(), "shop"));
        assertThrows(IllegalArgumentException.class, () -> KeygenMain.run(dir, List.of("a"), List.of(), "sh op"));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void writesBoundaryKeyWhenAbsent(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        byte[] key = Base64Url.decode(Files.readString(dir.resolve("boundary.key")).trim());
        assertEquals(32, key.length);
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(dir.resolve("boundary.key")));
    }

    // Rotating the boundary key makes every entry sent under the old one unopenable, so a re-run keeps it, while
    // every other key is new.
    @Test
    void keepsExistingBoundaryKey(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");
        byte[] boundary = Files.readAllBytes(dir.resolve("boundary.key"));
        byte[] gateway = Files.readAllBytes(dir.resolve("gateway.key"));

        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        assertArrayEquals(boundary, Files.readAllBytes(dir.resolve("boundary.key")));
        assertFalse(java.util.Arrays.equals(gateway, Files.readAllBytes(dir.resolve("gateway.key"))),
                "the other keys are regenerated");
    }

    // An existing boundary key that is not 32 bytes would fail the egress on every start, and replacing it would
    // make earlier entries unopenable, so the run is refused, naming the file, before anything is written.
    @Test
    void refusesAnExistingBoundaryKeyThatIsNot32Bytes(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boundary.key");
        for (String text : List.of("", "\n", Base64Url.encode(new byte[31]), Base64Url.encode(new byte[33]),
                Base64Url.encode(new byte[32]).substring(0, 20), "not base64!")) {
            Files.writeString(file, text);

            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop"), text);

            assertTrue(e.getMessage().contains(file.toString()), e.getMessage());
            assertTrue(e.getMessage().contains("32 bytes"), e.getMessage());
            assertEquals(text, Files.readString(file), "the file is left as it was");
            assertFalse(Files.exists(dir.resolve("keyring.json")), "nothing is written");
        }
    }

    @Test
    void keepsAnExistingBoundaryKeyWithSurroundingWhitespace(@TempDir Path dir) throws Exception {
        String text = "  " + Base64Url.encode(new byte[32]) + "\n\n";
        Files.writeString(dir.resolve("boundary.key"), text);

        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        assertEquals(text, Files.readString(dir.resolve("boundary.key")));
    }
}
