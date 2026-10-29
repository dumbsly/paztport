// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import org.paztport.core.encoding.Base64Url;

/**
 * Reads the private-key files keygen writes: base64url of the PKCS#8 encoding,
 * with any surrounding whitespace ignored. Every service, tool and demo loads
 * its key through here so the file format has a single reader.
 */
public final class KeyFiles {

    private KeyFiles() {
    }

    public static PrivateKey loadPrivateKey(Path file) {
        try {
            return Crypto.decodePrivateKey(Base64Url.decode(Files.readString(file).trim()));
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }
}
