// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
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
        assertEquals("failed to read " + missing, e.getMessage());
    }

    /** What a key file may not be surrounded by: whitespace to other tools, but not to JSON. */
    static final List<String> NOT_JSON_WHITESPACE = List.of("\u00a0", "\u000b", "\u000c", "\u0085", "\ufeff", "\u3000");

    @Test
    void ignoresExactlyTheFourJsonWhitespaceCharactersAroundAPrivateKey() throws Exception {
        KeyPair pair = Crypto.generateEd25519KeyPair();
        Path file = dir.resolve("svc.key");
        Files.writeString(file, " \t\r\n" + Base64Url.encode(pair.getPrivate().getEncoded()) + "\n\r\t ");

        assertArrayEquals(pair.getPrivate().getEncoded(), KeyFiles.loadPrivateKey(file).getEncoded());
    }

    @Test
    void aPrivateKeySurroundedByAnyOtherCharacterDoesNotRead() throws Exception {
        String key = Base64Url.encode(Crypto.generateEd25519KeyPair().getPrivate().getEncoded());
        Path file = dir.resolve("svc.key");
        for (String c : NOT_JSON_WHITESPACE) {
            Files.writeString(file, c + key);
            assertThrows(IllegalArgumentException.class, () -> KeyFiles.loadPrivateKey(file), "leading U+" + Integer.toHexString(c.codePointAt(0)));
            Files.writeString(file, key + c);
            assertThrows(IllegalArgumentException.class, () -> KeyFiles.loadPrivateKey(file), "trailing U+" + Integer.toHexString(c.codePointAt(0)));
        }
    }

    @Test
    void aPinIsTrimmedOfExactlyTheFourJsonWhitespaceCharacters() throws Exception {
        Path file = dir.resolve("policy.pub");
        Files.writeString(file, " \t\r\nabc\n\r\t ");
        assertEquals("abc", KeyFiles.loadPolicyPin(file));
        for (String c : NOT_JSON_WHITESPACE) {
            Files.writeString(file, c + "abc" + c);
            assertEquals(c + "abc" + c, KeyFiles.loadPolicyPin(file), "U+" + Integer.toHexString(c.codePointAt(0)));
        }
    }
}
