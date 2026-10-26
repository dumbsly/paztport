// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.Keyring;
import org.paztport.core.KeyringFile;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;

/** Loads the keygen/policy-tool output files into the in-memory types core needs. */
final class ConfigLoader {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ConfigLoader() {
    }

    static PrivateKey loadPrivateKey(Path file) {
        return Crypto.decodePrivateKey(Base64Url.decode(readString(file).trim()));
    }

    static Keyring loadKeyring(Path file) {
        return Keyring.fromFile(readKeyringFile(file));
    }

    static PublicKey loadPolicyKey(Path keyringFile) {
        return Crypto.decodePublicKey(Base64Url.decode(readKeyringFile(keyringFile).policy()));
    }

    static SignedRoot loadSignedRoot(Path file) {
        return read(file, SignedRoot.class);
    }

    static ProofBundle loadProofBundle(Path file) {
        return read(file, ProofBundle.class);
    }

    private static KeyringFile readKeyringFile(Path file) {
        return read(file, KeyringFile.class);
    }

    private static <T> T read(Path file, Class<T> type) {
        try {
            return JSON.readValue(Files.readAllBytes(file), type);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }

    private static String readString(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }
}
