// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;

/**
 * One-shot CLI: generate per-service keypairs and the keyring.
 *
 * <pre>keygen [outDir] [service...]</pre>
 *
 * Defaults to {@code out/keys} and the four POC services. Only service IDs are
 * logged; private key material never is.
 */
public final class KeygenMain {

    private static final List<String> DEFAULT_SERVICES = List.of("gateway", "orders", "payment", "search");
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private KeygenMain() {
    }

    public static void run(Path outDir, List<String> services) throws IOException {
        Files.createDirectories(outDir);
        KeyGenerator.Result result = KeyGenerator.generate(services);

        MAPPER.writeValue(outDir.resolve("keyring.json").toFile(), KeyGenerator.toKeyring(result));

        for (Map.Entry<String, KeyPair> e : result.services().entrySet()) {
            writePrivateKey(outDir.resolve(e.getKey() + ".key"), e.getValue());
        }
        writePrivateKey(outDir.resolve("policy.key"), result.policy());
    }

    /**
     * Writes the key owner-read/write only. Permissions are set before the key
     * is written, and again on an existing file, so the key is never readable by
     * other users, even briefly. On non-POSIX filesystems the default applies.
     */
    private static void writePrivateKey(Path file, KeyPair kp) throws IOException {
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            if (Files.exists(file)) {
                Files.setPosixFilePermissions(file, ownerOnly);
            } else {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(ownerOnly));
            }
        }
        Files.writeString(file, Base64Url.encode(Crypto.encodePrivateKey(kp.getPrivate())));
    }

    public static void main(String[] args) throws IOException {
        Path outDir = Path.of(args.length > 0 ? args[0] : "out/keys");
        List<String> services = args.length > 1 ? List.of(args).subList(1, args.length) : DEFAULT_SERVICES;

        run(outDir, services);
        System.out.println("keygen: wrote keyring + " + services.size() + " service keys + policy key to " + outDir);
    }
}
