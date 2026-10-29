// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.encoding.Base64Url;

class KeyFilesTest {

    @TempDir
    Path dir;

    @Test
    void readsABase64UrlPkcs8KeyAndIgnoresSurroundingWhitespace() throws Exception {
        KeyPair pair = Crypto.generateEd25519KeyPair();
        Path file = dir.resolve("svc.key");
        Files.writeString(file, Base64Url.encode(pair.getPrivate().getEncoded()) + "\n");

        assertArrayEquals(pair.getPrivate().getEncoded(), KeyFiles.loadPrivateKey(file).getEncoded());
    }

    @Test
    void aMissingFileIsAnUncheckedIoErrorNamingTheFile() {
        Path missing = dir.resolve("absent.key");
        UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> KeyFiles.loadPrivateKey(missing));
        org.junit.jupiter.api.Assertions.assertEquals("failed to read " + missing, e.getMessage());
    }
}
