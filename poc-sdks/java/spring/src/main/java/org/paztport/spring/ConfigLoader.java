// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.paztport.core.Base64Url;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.KeyringFile;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

/** Loads the keygen/policy-tool output files into the in-memory types core needs. */
final class ConfigLoader {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ConfigLoader() {
    }

    /** The keyring as written; it is trusted only once it verifies under the pin. */
    static KeyringFile loadKeyringFile(Path file) {
        return read(file, KeyringFile.class);
    }

    /**
     * The pinned policy key: the trimmed text of {@code policy.pub}, a base64url SPKI string. It comes from its
     * own file, never from the keyring it vouches for.
     */
    static String loadPolicyPin(Path file) {
        try {
            return Files.readString(file).trim();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }

    /**
     * The boundary key: the trimmed text of the file, base64url of exactly 32 bytes. Anything else fails here, at
     * startup, naming {@code property} but never the file's content.
     */
    static byte[] loadBoundaryKey(Path file, String property) {
        String text;
        try {
            text = Files.readString(file).trim();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
        byte[] key;
        try {
            key = Base64Url.decode(text);
        } catch (IllegalArgumentException e) {
            key = null;
        }
        if (key == null || key.length != BoundaryInfluence.KEY_LENGTH) {
            throw new IllegalStateException(property + " must hold " + BoundaryInfluence.KEY_LENGTH
                    + " bytes as base64url: " + file);
        }
        return key;
    }

    static SignedRoot loadSignedRoot(Path file) {
        return read(file, SignedRoot.class);
    }

    static ProofBundle loadProofBundle(Path file) {
        return read(file, ProofBundle.class);
    }

    private static <T> T read(Path file, Class<T> type) {
        try {
            return JSON.readValue(Files.readAllBytes(file), type);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }
}
