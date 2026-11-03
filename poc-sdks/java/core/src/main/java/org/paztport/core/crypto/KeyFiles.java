// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PrivateKey;
import java.util.Set;
import org.paztport.core.encoding.Base64Url;

/**
 * Reads, and writes, the key files keygen writes: a private key as base64url of the PKCS#8 encoding, the policy pin as
 * base64url of the SPKI, with the surrounding JSON whitespace (space, tab, line feed and carriage return)
 * ignored and nothing else. Every service, tool and demo loads its keys through here so the file format has a
 * single reader.
 */
public final class KeyFiles {

    private KeyFiles() {
    }

    /**
     * The text of a key file without its surrounding space, tab, line feed and carriage return, the whitespace of
     * RFC 8259. Any other character, a byte order mark or a no-break space included, stays in the text.
     *
     * @throws UncheckedIOException when the file cannot be read
     */
    public static String text(Path file) {
        String raw;
        try {
            raw = Files.readString(file);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
        int from = 0;
        int to = raw.length();
        while (from < to && isJsonWhitespace(raw.charAt(from))) {
            from++;
        }
        while (to > from && isJsonWhitespace(raw.charAt(to - 1))) {
            to--;
        }
        return raw.substring(from, to);
    }

    private static boolean isJsonWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    public static PrivateKey loadPrivateKey(Path file) {
        return Crypto.decodePrivateKey(Base64Url.decode(text(file)));
    }

    /**
     * The pinned policy key: the text of {@code policy.pub} without its surrounding JSON whitespace, a base64url
     * SPKI string. It comes from its own file, never from the keyring it vouches for.
     */
    public static String loadPolicyPin(Path file) {
        return text(file);
    }

    /** Writes {@code key} as keygen does: base64url of its PKCS#8 encoding, readable by {@link #loadPrivateKey}. */
    public static void writePrivateKey(Path file, PrivateKey key) throws IOException {
        writeSecret(file, Base64Url.encode(Crypto.encodePrivateKey(key)));
    }

    /**
     * Writes {@code content} to {@code file}, owner-read/write only. Permissions are set before the content is
     * written, and again on an existing file, so the content is never readable by other users, even briefly. On
     * non-POSIX filesystems the default applies.
     */
    public static void writeSecret(Path file, String content) throws IOException {
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            if (Files.exists(file)) {
                Files.setPosixFilePermissions(file, ownerOnly);
            } else {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(ownerOnly));
            }
        }
        Files.writeString(file, content);
    }
}
