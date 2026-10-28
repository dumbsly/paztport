// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.Base64Url;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;

/**
 * One-shot CLI: generate per-service keypairs, the signed keyring, the policy pin, and TLS certificates.
 *
 * <pre>keygen [outDir] [service...] [--tls-only name...] [--org name]</pre>
 *
 * Defaults to {@code out/keys}, the four POC services, the TLS-only names {@code operator} and
 * {@code responder} (they speak mTLS but sign no stamps, so stay out of the keyring), and org {@code shop}.
 * One CA is made per run and every certificate is issued from it. {@code tls/} holds {@code ca.crt} and the leaf
 * certificates and keys, and is what gets mounted; the CA key is written alone to {@code ca/ca.key}. {@code ca} is
 * therefore not a usable name, and names must be unique across services and TLS-only names. Only names are logged; private key material
 * never is.
 *
 * <p>Every key is new on each run except {@code boundary.key}, the egress's boundary key (32 random bytes as
 * base64url), which is written only when it does not exist: rotating it would make every influence entry the
 * egress has sent unopenable. An existing one that does not decode to 32 bytes is refused, naming the file, before
 * anything is written: kept, it would fail the egress on every start, and replaced, it would rotate the key. It
 * belongs to the one egress service of the mesh and its replicas, never to another service.
 */
public final class KeygenMain {

    private static final List<String> DEFAULT_SERVICES = List.of("gateway", "orders", "payment", "search");
    private static final List<String> DEFAULT_TLS_ONLY = List.of("operator", "responder");
    private static final Duration TLS_VALIDITY = Duration.ofDays(825);
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private KeygenMain() {
    }

    public static void run(Path outDir, List<String> services, List<String> tlsOnly, String org) throws IOException {
        List<String> names = new ArrayList<>(services);
        names.addAll(tlsOnly);
        Set<String> seen = new HashSet<>();
        for (String name : names) {
            TlsIssuer.requireLabel(name);
            if (name.equals("ca")) {
                throw new IllegalArgumentException("'ca' is reserved for the certificate authority");
            }
            if (!seen.add(name)) {
                throw new IllegalArgumentException("duplicate name: " + name);
            }
        }
        TlsIssuer.requireLabel(org);
        Path boundaryKey = outDir.resolve("boundary.key");
        boolean keepBoundaryKey = Files.exists(boundaryKey, LinkOption.NOFOLLOW_LINKS);
        if (keepBoundaryKey) {
            requireBoundaryKey(boundaryKey);
        }
        Files.createDirectories(outDir);
        KeyGenerator.Result result = KeyGenerator.generate(services);

        MAPPER.writeValue(outDir.resolve("keyring.json").toFile(), KeyGenerator.toKeyring(result));
        Files.writeString(outDir.resolve("policy.pub"), KeyGenerator.policyPublicKey(result) + "\n");

        for (Map.Entry<String, KeyPair> e : result.services().entrySet()) {
            writePrivateKey(outDir.resolve(e.getKey() + ".key"), e.getValue());
        }
        writePrivateKey(outDir.resolve("policy.key"), result.policy());
        if (!keepBoundaryKey) {
            byte[] key = new byte[BoundaryInfluence.KEY_LENGTH];
            new SecureRandom().nextBytes(key);
            writeSecret(boundaryKey, Base64Url.encode(key) + "\n");
        }

        Path tls = Files.createDirectories(outDir.resolve("tls"));
        TlsIssuer.Ca ca = TlsIssuer.newCa(org, TLS_VALIDITY);
        Files.writeString(tls.resolve("ca.crt"), TlsIssuer.pem(ca.cert()));
        // Its own directory: tls/ is mounted into containers, and the CA key must never be.
        writeSecret(Files.createDirectories(outDir.resolve("ca")).resolve("ca.key"),
                TlsIssuer.pem(ca.keys().getPrivate()));
        for (String name : names) {
            TlsIssuer.Issued leaf = TlsIssuer.issue(ca, name, TLS_VALIDITY);
            Files.writeString(tls.resolve(name + ".crt"), TlsIssuer.pem(leaf.cert()));
            writeSecret(tls.resolve(name + ".key"), TlsIssuer.pem(leaf.keys().getPrivate()));
        }
    }

    /**
     * Throws unless the existing boundary key is, as the egress reads it, base64url of exactly 32 bytes once trimmed.
     * The message names the file but never its content.
     */
    private static void requireBoundaryKey(Path file) throws IOException {
        byte[] key;
        try {
            key = Base64Url.decode(Files.readString(file).trim());
        } catch (IllegalArgumentException e) {
            key = null;
        }
        if (key == null || key.length != BoundaryInfluence.KEY_LENGTH) {
            throw new IllegalStateException(file + " exists but does not hold " + BoundaryInfluence.KEY_LENGTH
                    + " bytes as base64url. It is kept across runs, since a new one would make every entry sent"
                    + " under it unopenable, so it is not replaced: restore it, or delete it to start a new key.");
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

    /** Parsed command line. */
    record Args(Path outDir, List<String> services, List<String> tlsOnly, String org) {
    }

    /** {@code --tls-only} with no names means none; leaving it out means the defaults, whatever the flag order. */
    static Args parse(String[] args) {
        List<String> positional = new ArrayList<>();
        List<String> tlsOnly = new ArrayList<>();
        String org = "shop";
        boolean sawTlsOnly = false;
        boolean inTlsOnly = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--tls-only")) {
                sawTlsOnly = true;
                inTlsOnly = true;
            } else if (args[i].equals("--org")) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("--org needs a name");
                }
                org = args[++i];
                inTlsOnly = false;
            } else if (inTlsOnly) {
                tlsOnly.add(args[i]);
            } else {
                positional.add(args[i]);
            }
        }
        return new Args(Path.of(positional.isEmpty() ? "out/keys" : positional.get(0)),
                positional.size() > 1 ? List.copyOf(positional.subList(1, positional.size())) : DEFAULT_SERVICES,
                sawTlsOnly ? tlsOnly : DEFAULT_TLS_ONLY, org);
    }

    public static void main(String[] args) throws IOException {
        try {
            Args a = parse(args);
            run(a.outDir(), a.services(), a.tlsOnly(), a.org());
            System.out.println("keygen: wrote signed keyring, policy pin, " + a.services().size()
                    + " service keys, policy key and TLS certificates to " + a.outDir()
                    + " (boundary key written only if absent)");
        } catch (IllegalArgumentException e) {
            System.err.println("keygen: " + e.getMessage());
            System.err.println("usage: keygen [outDir] [service...] [--tls-only name...] [--org name]");
            System.exit(2);
        } catch (IllegalStateException e) {
            System.err.println("keygen: " + e.getMessage());
            System.exit(1);
        }
    }
}
