// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.policy.OwnMaterial;

/**
 * One-shot CLI: generate per-service keypairs, the signed keyring, the policy pin, and TLS certificates. The keyring
 * is signed and vouches for its keys for {@code PAZTPORT_POLICY_DAYS} days from the run (default 7), the setting the
 * policy tool reads for the roots and keyrings it signs.
 *
 * <pre>keygen &lt;outDir&gt; &lt;service&gt;... [--tls-only name...] --org &lt;name&gt;</pre>
 *
 * The output directory, at least one service and the organisation, which names the CA, are required. TLS-only
 * names, which speak mTLS but sign no stamps and so stay out of the keyring, are made only when named.
 * One CA is made per run and every certificate is issued from it. {@code tls/} holds {@code ca.crt} and the leaf
 * certificates and keys, and is what gets mounted; the CA key is written alone to {@code ca/ca.key}. {@code ca} is
 * therefore not a usable name, and names must be unique across services and TLS-only names. Only names are
 * logged; private key material never is.
 *
 * <p>Every key is new on each run except {@code boundary.key}, the egress's boundary key (32 random bytes as
 * base64url), which is written only when it does not exist: rotating it would make every influence entry the
 * egress has sent unopenable. An existing one that does not decode to 32 bytes is refused, naming the file, before
 * anything is written: kept, it would fail the egress on every start, and replaced, it would rotate the key. It
 * belongs to the one egress service of the mesh and its replicas, never to another service.
 */
public final class KeygenMain {

    private static final Duration TLS_VALIDITY = Duration.ofDays(825);

    private KeygenMain() {
    }

    /** As {@link #run(Path, List, List, String, long)}, the keyring vouching for its keys for seven days from now. */
    public static void run(Path outDir, List<String> services, List<String> tlsOnly, String org) throws IOException {
        run(outDir, services, tlsOnly, org, System.currentTimeMillis() + OwnMaterial.DEFAULT_LIFETIME_MS);
    }

    /** Writes every file, the keyring signed until {@code keyringNotAfter} (milliseconds since the epoch). */
    public static void run(Path outDir, List<String> services, List<String> tlsOnly, String org, long keyringNotAfter)
            throws IOException {
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

        Files.writeString(outDir.resolve("keyring.json"), KeyGenerator.toKeyring(result, keyringNotAfter).toFile());
        Files.writeString(outDir.resolve("policy.pub"), KeyGenerator.policyPublicKey(result) + "\n");

        for (Map.Entry<String, KeyPair> e : result.services().entrySet()) {
            KeyFiles.writePrivateKey(outDir.resolve(e.getKey() + ".key"), e.getValue().getPrivate());
        }
        KeyFiles.writePrivateKey(outDir.resolve("policy.key"), result.policy().getPrivate());
        if (!keepBoundaryKey) {
            byte[] key = new byte[BoundaryInfluence.KEY_LENGTH];
            new SecureRandom().nextBytes(key);
            KeyFiles.writeSecret(boundaryKey, Base64Url.encode(key) + "\n");
        }

        Path tls = Files.createDirectories(outDir.resolve("tls"));
        TlsIssuer.Ca ca = TlsIssuer.newCa(org, TLS_VALIDITY);
        Files.writeString(tls.resolve("ca.crt"), TlsIssuer.pem(ca.cert()));
        // Its own directory: tls/ is mounted into containers, and the CA key must never be.
        KeyFiles.writeSecret(Files.createDirectories(outDir.resolve("ca")).resolve("ca.key"),
                TlsIssuer.pem(ca.keys().getPrivate()));
        for (String name : names) {
            TlsIssuer.Issued leaf = TlsIssuer.issue(ca, name, TLS_VALIDITY);
            Files.writeString(tls.resolve(name + ".crt"), TlsIssuer.pem(leaf.cert()));
            KeyFiles.writeSecret(tls.resolve(name + ".key"), TlsIssuer.pem(leaf.keys().getPrivate()));
        }
    }

    /**
     * Throws unless the existing boundary key is, as the egress reads it, base64url of exactly 32 bytes once its
     * surrounding JSON whitespace is removed. The message names the file but never its content.
     */
    private static void requireBoundaryKey(Path file) throws IOException {
        byte[] key;
        try {
            key = Base64Url.decode(KeyFiles.text(file));
        } catch (IllegalArgumentException e) {
            key = null;
        }
        if (key == null || key.length != BoundaryInfluence.KEY_LENGTH) {
            throw new IllegalStateException(file + " exists but does not hold " + BoundaryInfluence.KEY_LENGTH
                    + " bytes as base64url. It is kept across runs, since a new one would make every entry sent"
                    + " under it unopenable, so it is not replaced: restore it, or delete it to start a new key.");
        }
    }

    /** The keyring's {@code notAfter}: see {@link OwnMaterial#daysFromNow}. */
    static long keyringNotAfter(String days, long nowMs) {
        return OwnMaterial.daysFromNow("PAZTPORT_POLICY_DAYS", days, nowMs);
    }

    /** Parsed command line. */
    record Args(Path outDir, List<String> services, List<String> tlsOnly, String org) {
    }

    /**
     * Needs the output directory, one service or more, and {@code --org}. The names after {@code --tls-only} are the
     * TLS-only identities, whatever the flag order; without them there are none.
     */
    static Args parse(String[] args) {
        List<String> positional = new ArrayList<>();
        List<String> tlsOnly = new ArrayList<>();
        String org = null;
        boolean inTlsOnly = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--tls-only")) {
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
        if (positional.size() < 2) {
            throw new IllegalArgumentException("needs an output directory and at least one service");
        }
        if (org == null) {
            throw new IllegalArgumentException("needs --org");
        }
        return new Args(Path.of(positional.get(0)), List.copyOf(positional.subList(1, positional.size())),
                tlsOnly, org);
    }

    public static void main(String[] args) throws IOException {
        try {
            Args a = parse(args);
            long notAfter = keyringNotAfter(System.getenv("PAZTPORT_POLICY_DAYS"), System.currentTimeMillis());
            run(a.outDir(), a.services(), a.tlsOnly(), a.org(), notAfter);
            System.out.println("keygen: wrote signed keyring (notAfter " + notAfter + ", "
                    + Instant.ofEpochMilli(notAfter) + "), policy pin, " + a.services().size()
                    + " service keys, policy key and TLS certificates to " + a.outDir()
                    + " (boundary key written only if absent)");
        } catch (IllegalArgumentException e) {
            System.err.println("keygen: " + e.getMessage());
            System.err.println("usage: keygen <outDir> <service>... [--tls-only name...] --org <name>");
            System.exit(2);
        } catch (IllegalStateException e) {
            System.err.println("keygen: " + e.getMessage());
            System.exit(1);
        }
    }
}
