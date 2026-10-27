// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;

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

        KeyringFile keyring = new ObjectMapper()
                .readValue(Files.readAllBytes(dir.resolve("keyring.json")), KeyringFile.class);
        for (String svc : SERVICES) {
            assertTrue(keyring.services().containsKey(svc));
        }
        assertTrue(keyring.policy() != null && !keyring.policy().isBlank());
    }

    @Test
    void writtenPrivateKeySignsWhatTheKeyringPublicKeyVerifies(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = new ObjectMapper()
                .readValue(Files.readAllBytes(dir.resolve("keyring.json")), KeyringFile.class);

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

        KeyringFile keyring = new ObjectMapper()
                .readValue(Files.readAllBytes(dir.resolve("keyring.json")), KeyringFile.class);
        String pin = Files.readString(dir.resolve("policy.pub")).trim();
        assertEquals(keyring.policy(), pin);
        assertTrue(keyring.verifies(pin));
        assertTrue(!keyring.verifies(Base64Url.encode(
                Crypto.encodePublicKey(Crypto.generateEd25519KeyPair().getPublic()))));
    }

    @Test
    void tlsOnlyNamesGetCertificatesButNeverEnterTheKeyring(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        KeyringFile keyring = new ObjectMapper()
                .readValue(Files.readAllBytes(dir.resolve("keyring.json")), KeyringFile.class);
        for (String name : TLS_ONLY) {
            assertTrue(!keyring.services().containsKey(name), name);
            assertTrue(!Files.exists(dir.resolve(name + ".key")), name + " has no stamp key");
        }
        for (String name : List.of("gateway", "orders", "payment", "search", "operator", "responder")) {
            assertTrue(Files.exists(dir.resolve("tls/" + name + ".crt")), name);
            assertTrue(Files.readString(dir.resolve("tls/" + name + ".key")).startsWith("-----BEGIN PRIVATE KEY-----"));
        }
        assertTrue(Files.exists(dir.resolve("tls/ca.crt")));
        assertTrue(Files.exists(dir.resolve("tls/ca.key")));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void tlsPrivateKeysAreOwnerOnlyIncludingTheCa(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES, TLS_ONLY, "shop");

        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        for (String name : List.of("ca", "gateway", "operator", "responder")) {
            assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve("tls/" + name + ".key")), name);
        }
    }
}
