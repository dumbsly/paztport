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

    @Test
    void writesKeyringAndOnePrivateKeyFilePerServicePlusPolicy(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES);

        assertTrue(Files.exists(dir.resolve("keyring.json")));
        assertTrue(Files.exists(dir.resolve("policy.key")));
        for (String svc : SERVICES) {
            assertTrue(Files.exists(dir.resolve(svc + ".key")), "missing private key for " + svc);
        }
    }

    @Test
    void keyringJsonParsesAndCoversEveryService(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES);

        KeyringFile keyring = new ObjectMapper()
                .readValue(Files.readAllBytes(dir.resolve("keyring.json")), KeyringFile.class);
        for (String svc : SERVICES) {
            assertTrue(keyring.services().containsKey(svc));
        }
        assertTrue(keyring.policy() != null && !keyring.policy().isBlank());
    }

    @Test
    void writtenPrivateKeySignsWhatTheKeyringPublicKeyVerifies(@TempDir Path dir) throws Exception {
        KeygenMain.run(dir, SERVICES);

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
        KeygenMain.run(dir, SERVICES);
        // A pre-existing, loosened key file must be tightened on re-run.
        Files.setPosixFilePermissions(dir.resolve("gateway.key"), PosixFilePermissions.fromString("rw-r--r--"));
        KeygenMain.run(dir, SERVICES);

        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve("policy.key")));
        for (String svc : SERVICES) {
            assertEquals(ownerOnly, Files.getPosixFilePermissions(dir.resolve(svc + ".key")), svc);
        }
    }
}
