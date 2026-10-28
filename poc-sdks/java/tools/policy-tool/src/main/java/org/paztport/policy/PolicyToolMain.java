// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.List;
import org.paztport.core.KeyFiles;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.ProofBundle;
import org.paztport.core.ReplyCert;
import org.paztport.core.SignedRoot;

/**
 * CLI: build a signed root and per-service proof bundles from paths.yaml.
 *
 * <pre>policy-tool [paths.yaml] [keysDir] [outDir]</pre>
 *
 * Reads the policy private key from {@code keysDir/policy.key}. Depth comes from
 * {@code PAZTPORT_PROOF_DEPTH} (default 8). The root is signed in the new form and
 * vouches for its routes for seven days from the run. Only root id, its
 * {@code notAfter} and service names are logged, never salts or the tree.
 *
 * <p>When {@code PAZTPORT_REPLY_CERT_SVC} names a service, it also writes {@code reply-cert.json}, a
 * {@link ReplyCert} for that service's key in {@code keysDir/keyring.json}, valid for
 * {@code PAZTPORT_REPLY_CERT_DAYS} days (default 7). It is reissued on every run, and a key that is not reissued
 * stops being accepted when its certificate expires. Before writing anything it checks that the keyring is
 * signed by this policy key and names the service, since that check is what a certificate vouches for; on a
 * refusal it writes nothing and exits 2. It prints only the service and {@code notAfter}, never key material.
 */
public final class PolicyToolMain {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final long DAY_MS = 86_400_000L;
    private static final int DEFAULT_REPLY_CERT_DAYS = 7;
    private static final int DEFAULT_ROOT_DAYS = 7;

    private PolicyToolMain() {
    }

    /** Writes the root, valid for seven days from now, and the bundles; no reply certificate. */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth) throws IOException {
        run(pathsYaml, keysDir, outDir, depth, null, 0);
    }

    /**
     * As {@link #run(Path, Path, Path, int)}, and when {@code replyCertSvc} is not null also writes
     * {@code reply-cert.json} for that service, valid until {@code replyCertNotAfter}. Throws
     * {@link IllegalArgumentException}, having written nothing, when the keyring does not verify under the policy
     * key or lacks the service.
     */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth, String replyCertSvc,
            long replyCertNotAfter) throws IOException {
        run(pathsYaml, keysDir, outDir, depth, System.currentTimeMillis() + DEFAULT_ROOT_DAYS * DAY_MS, replyCertSvc,
                replyCertNotAfter);
    }

    /**
     * As {@link #run(Path, Path, Path, int, String, long)}, with the root signed until {@code rootNotAfter}. Signing
     * it vouches that every route in {@code paths.yaml} is allowed until then: the file is the policy owner's
     * statement of the routes it currently allows.
     */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth, long rootNotAfter,
            String replyCertSvc, long replyCertNotAfter) throws IOException {
        List<List<String>> routes = PathsReader.parse(Files.readAllBytes(pathsYaml));
        PrivateKey policyKey = KeyFiles.loadPrivateKey(keysDir.resolve("policy.key"));
        ReplyCert cert = replyCertSvc == null ? null
                : issueReplyCert(keysDir.resolve("keyring.json"), replyCertSvc, replyCertNotAfter, policyKey);

        PolicyBuilder.Result result = PolicyBuilder.build(routes, depth, rootNotAfter, policyKey);

        Files.createDirectories(outDir);
        MAPPER.writeValue(outDir.resolve("root.json").toFile(), result.signedRoot());
        for (ProofBundle bundle : result.bundles().values()) {
            MAPPER.writeValue(outDir.resolve("proofs-" + bundle.service() + ".json").toFile(), bundle);
        }
        if (cert != null) {
            MAPPER.writeValue(outDir.resolve("reply-cert.json").toFile(), cert.toJson());
        }
    }

    /**
     * The certificate for {@code svc}'s key in the keyring, after the checks it vouches for: the keyring verifies
     * under its own policy key, that key is the one in {@code policy.key} (the certificate signed with it must
     * verify under the keyring's policy key), and the keyring names the service.
     */
    private static ReplyCert issueReplyCert(Path keyringFile, String svc, long notAfter, PrivateKey policyKey) {
        KeyringFile ring;
        try {
            ring = KeyringFile.load(keyringFile);
        } catch (UncheckedIOException | IllegalArgumentException e) {
            throw new IllegalArgumentException(keyringFile + " is missing or not a keyring", e);
        }
        if (ring.policy() == null || !ring.verifies(ring.policy())) {
            throw new IllegalArgumentException(keyringFile + " is not signed by its policy key");
        }
        String key = ring.services().get(svc);
        if (key == null) {
            throw new IllegalArgumentException(keyringFile + " has no key for service " + svc);
        }
        ReplyCert cert = ReplyCert.issue(ring.policy(), svc, key, notAfter, policyKey);
        if (!cert.verifies(ring.policy())) {
            throw new IllegalArgumentException(keyringFile + " is not signed by this policy key (policy.key)");
        }
        return cert;
    }

    /** Now plus {@code days} days (default 7 when null); refuses anything but a positive whole number of days. */
    static long replyCertNotAfter(String days, long nowMs) {
        int d;
        try {
            d = days == null ? DEFAULT_REPLY_CERT_DAYS : Integer.parseInt(days);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("PAZTPORT_REPLY_CERT_DAYS must be a positive whole number of days");
        }
        if (d < 1) {
            throw new IllegalArgumentException("PAZTPORT_REPLY_CERT_DAYS must be a positive whole number of days");
        }
        return nowMs + d * DAY_MS;
    }

    public static void main(String[] args) throws IOException {
        Path pathsYaml = Path.of(args.length > 0 ? args[0] : "policy/paths.yaml");
        Path keysDir = Path.of(args.length > 1 ? args[1] : "out/keys");
        Path outDir = Path.of(args.length > 2 ? args[2] : "out/policy");
        int depth = Integer.parseInt(System.getenv().getOrDefault("PAZTPORT_PROOF_DEPTH", "8"));
        String replyCertSvc = System.getenv("PAZTPORT_REPLY_CERT_SVC");

        long notAfter = 0;
        try {
            if (replyCertSvc != null) {
                notAfter = replyCertNotAfter(System.getenv("PAZTPORT_REPLY_CERT_DAYS"), System.currentTimeMillis());
            }
            run(pathsYaml, keysDir, outDir, depth, replyCertSvc, notAfter);
        } catch (IllegalArgumentException e) {
            System.err.println("policy-tool: " + e.getMessage());
            System.exit(2);
        }

        SignedRoot root = SignedRoot.load(outDir.resolve("root.json"));
        System.out.println("policy-tool: wrote root " + root.rootId() + ", notAfter " + root.notAfter() + " ("
                + Instant.ofEpochMilli(root.notAfter()) + "), and per-service bundles to " + outDir);
        if (replyCertSvc != null) {
            System.out.println("policy-tool: wrote reply certificate for " + replyCertSvc + ", notAfter " + notAfter
                    + " (" + Instant.ofEpochMilli(notAfter) + ")");
        }
    }
}
