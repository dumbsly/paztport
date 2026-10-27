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
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;

/**
 * One-shot CLI: generate per-service keypairs, the signed keyring, the policy pin, and TLS certificates.
 *
 * <pre>keygen [outDir] [service...] [--tls-only name...] [--org name]</pre>
 *
 * Defaults to {@code out/keys}, the four POC services, the TLS-only names {@code operator} and
 * {@code responder} (they speak mTLS but sign no stamps, so stay out of the keyring), and org {@code shop}.
 * One CA is made per run and every certificate is issued from it. Only names are logged; private key material
 * never is.
 */
public final class KeygenMain {

    private static final List<String> DEFAULT_SERVICES = List.of("gateway", "orders", "payment", "search");
    private static final List<String> DEFAULT_TLS_ONLY = List.of("operator", "responder");
    private static final Duration TLS_VALIDITY = Duration.ofDays(825);
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private KeygenMain() {
    }

    public static void run(Path outDir, List<String> services, List<String> tlsOnly, String org) throws IOException {
        Files.createDirectories(outDir);
        KeyGenerator.Result result = KeyGenerator.generate(services);

        MAPPER.writeValue(outDir.resolve("keyring.json").toFile(), KeyGenerator.toKeyring(result));
        Files.writeString(outDir.resolve("policy.pub"), KeyGenerator.policyPublicKey(result) + "\n");

        for (Map.Entry<String, KeyPair> e : result.services().entrySet()) {
            writePrivateKey(outDir.resolve(e.getKey() + ".key"), e.getValue());
        }
        writePrivateKey(outDir.resolve("policy.key"), result.policy());

        Path tls = Files.createDirectories(outDir.resolve("tls"));
        TlsIssuer.Ca ca = TlsIssuer.newCa(org, TLS_VALIDITY);
        Files.writeString(tls.resolve("ca.crt"), TlsIssuer.pem(ca.cert()));
        writeSecret(tls.resolve("ca.key"), TlsIssuer.pem(ca.keys().getPrivate()));
        List<String> names = new ArrayList<>(services);
        names.addAll(tlsOnly);
        for (String name : names) {
            TlsIssuer.Issued leaf = TlsIssuer.issue(ca, name, TLS_VALIDITY);
            Files.writeString(tls.resolve(name + ".crt"), TlsIssuer.pem(leaf.cert()));
            writeSecret(tls.resolve(name + ".key"), TlsIssuer.pem(leaf.keys().getPrivate()));
        }
    }

    /**
     * Writes the key owner-read/write only. Permissions are set before the key
     * is written, and again on an existing file, so the key is never readable by
     * other users, even briefly. On non-POSIX filesystems the default applies.
     */
    private static void writePrivateKey(Path file, KeyPair kp) throws IOException {
        writeSecret(file, Base64Url.encode(Crypto.encodePrivateKey(kp.getPrivate())));
    }

    private static void writeSecret(Path file, String content) throws IOException {
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

    public static void main(String[] args) throws IOException {
        List<String> positional = new ArrayList<>();
        List<String> tlsOnly = new ArrayList<>();
        String org = "shop";
        boolean inTlsOnly = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--tls-only")) {
                inTlsOnly = true;
            } else if (args[i].equals("--org")) {
                if (i + 1 >= args.length) {
                    System.err.println("keygen: --org needs a name");
                    System.exit(2);
                }
                org = args[++i];
                inTlsOnly = false;
            } else if (inTlsOnly) {
                tlsOnly.add(args[i]);
            } else {
                positional.add(args[i]);
            }
        }
        Path outDir = Path.of(positional.isEmpty() ? "out/keys" : positional.get(0));
        List<String> services = positional.size() > 1 ? positional.subList(1, positional.size()) : DEFAULT_SERVICES;

        run(outDir, services, inTlsOnly || !tlsOnly.isEmpty() ? tlsOnly : DEFAULT_TLS_ONLY, org);
        System.out.println("keygen: wrote signed keyring, policy pin, " + services.size()
                + " service keys, policy key and TLS certificates to " + outDir);
    }
}
