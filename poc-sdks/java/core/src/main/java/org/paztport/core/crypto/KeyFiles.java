// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PrivateKey;
import java.util.Set;
import org.paztport.core.encoding.Base64Url;

/**
 * Reads, and writes, the key files keygen writes: a private key as base64url of the PKCS#8 encoding, the policy
 * pin as base64url of the SPKI, with the surrounding JSON whitespace (space, tab, line feed and carriage return)
 * ignored and nothing else. The Spring starter and the tools load their keys through here, so the Java SDK has one
 * reader of the format; an embedder that loads keys itself can do the same.
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

    /**
     * Writes {@code key} as keygen does: base64url of its PKCS#8 encoding, readable by {@link #loadPrivateKey}. It
     * overwrites as {@link #writeSecret} does, so it is for a fresh directory; {@link #createPrivateKey} never
     * replaces a file.
     */
    public static void writePrivateKey(Path file, PrivateKey key) throws IOException {
        writeSecret(file, Base64Url.encode(Crypto.encodePrivateKey(key)));
    }

    /**
     * Writes {@code content} to {@code file}, owner-read/write only. Permissions are set before the content is
     * written, and again on an existing file, so the content is never readable by other users, even briefly. On
     * non-POSIX filesystems the default applies.
     *
     * <p>It overwrites, and is meant for keygen's fresh directories, which hold nothing to keep: an existing file is
     * truncated and rewritten in place, not replaced atomically, so a failure part-way leaves it short, and a
     * symbolic link is followed, so its target is what is written. {@link #createNew} and {@link #createPrivateKey}
     * are for a directory that holds files to keep.
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

    /**
     * As {@link #writePrivateKey}, but only if {@code file} does not exist: the file is created, never replaced,
     * and what is already there, a symbolic link included, is left as it was. It is created owner-read/write only
     * from the start; on a file system without POSIX permissions it gets the default permissions instead.
     *
     * @throws FileAlreadyExistsException when {@code file} exists, even if it appeared an instant ago
     * @throws IOException when it cannot be created or written; a file this call created is then removed again
     */
    public static void createPrivateKey(Path file, PrivateKey key) throws IOException {
        create(file, Base64Url.encode(Crypto.encodePrivateKey(key)), true);
    }

    /**
     * Writes {@code content} to {@code file} with the default permissions, but only if it does not exist: what is
     * already there, a symbolic link included, is left as it was.
     *
     * @throws FileAlreadyExistsException when {@code file} exists, even if it appeared an instant ago
     * @throws IOException when it cannot be created or written; a file this call created is then removed again
     */
    public static void createNew(Path file, String content) throws IOException {
        create(file, content, false);
    }

    /**
     * Creates the file atomically, owner-only from the start where asked and the system has owners, so there is no
     * moment when another file of that name is truncated or the content is readable by others.
     */
    private static void create(Path file, String content, boolean ownerOnly) throws IOException {
        if (ownerOnly && file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.writeString(file, "", StandardOpenOption.CREATE_NEW);
        }
        // From here the file is this call's own, so a failure to fill it takes it away again, never another's.
        try {
            Files.writeString(file, content);
        } catch (IOException | RuntimeException e) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
    }
}
