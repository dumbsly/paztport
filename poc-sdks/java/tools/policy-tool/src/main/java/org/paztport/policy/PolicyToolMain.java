// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.PolicyOwner;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;

/**
 * CLI: build, or renew, a signed root and per-service proof bundles from paths.yaml, and re-sign the keyring beside
 * them.
 *
 * <pre>policy-tool [--renew] [paths.yaml] [keysDir] [outDir]</pre>
 *
 * Reads the policy private key from {@code keysDir/policy.key} and the keyring from {@code keysDir/keyring.json}. The
 * root and the keyring are signed to vouch for {@code PAZTPORT_POLICY_DAYS} days from the run (default 7). Two modes:
 *
 * <ul>
 *   <li>Rebuild, the default: a new salted tree from {@code paths.yaml} (depth from {@code PAZTPORT_PROOF_DEPTH},
 *       default 8), so a new {@code rootId}, new {@code root.json} and new bundles, which every holder must reload
 *       together; and the keyring re-signed.</li>
 *   <li>Renew, with {@code --renew} or {@code PAZTPORT_RENEW=true}: {@code outDir/root.json} and the keyring signed
 *       again with a new {@code notAfter}, the same {@code root} and {@code rootId}, so the bundles stay valid and
 *       are not touched, and holders can pick up the renewed files one at a time. {@code paths.yaml} is not
 *       read.</li>
 * </ul>
 *
 * Either mode first checks the keyring (and, renewing, the root) is signed by the policy key in {@code policy.key},
 * whether or not it has expired, and that the keyring names that key; on a refusal it writes nothing and exits 2.
 * The keyring is written in place, truncated and rewritten rather than replaced by a rename, so that it can be a
 * single file mounted into the tool. It is written first, so a keyring that cannot be written (mounted read-only,
 * say) stops the run with one line, {@code policy-tool: cannot write <file>: <reason>}, the reason being the file
 * system's ({@code Read-only file system}, {@code No space left on device}), and nothing written; that and any other
 * I/O error exit 1. Written in place, it is not written atomically: a crash or a full disk part-way through leaves
 * it empty or truncated, which the next run refuses as not a keyring. This tool only re-signs a keyring, never
 * writes one from nothing, so recovering from that means new keys from the keygen.
 *
 * <p>When {@code PAZTPORT_REPLY_CERT_SVC} names a service, either mode also writes {@code reply-cert.json}, a
 * {@link ReplyCert} for that service's key in the keyring, valid for {@code PAZTPORT_REPLY_CERT_DAYS} days
 * (default 7). It is reissued on every run, and a key that is not reissued stops being accepted when its
 * certificate expires. Before writing anything it checks that the keyring names the service, since that check is
 * what a certificate vouches for.
 *
 * <p>It prints only file names, each one's {@code notAfter} and the certificate's service; never key material,
 * salts or the tree.
 */
public final class PolicyToolMain {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final long DAY_MS = 86_400_000L;
    private static final int DEFAULT_DAYS = 7;

    private PolicyToolMain() {
    }

    /** Rebuilds with the root and keyring valid for seven days from now; no reply certificate. */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth) throws IOException {
        run(pathsYaml, keysDir, outDir, depth, null, 0);
    }

    /**
     * As {@link #run(Path, Path, Path, int)}, and when {@code replyCertSvc} is not null also writes
     * {@code reply-cert.json} for that service, valid until {@code replyCertNotAfter}.
     */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth, String replyCertSvc,
            long replyCertNotAfter) throws IOException {
        run(pathsYaml, keysDir, outDir, depth, System.currentTimeMillis() + DEFAULT_DAYS * DAY_MS, replyCertSvc,
                replyCertNotAfter);
    }

    /**
     * Rebuilds: a new tree from {@code paths.yaml} and its bundles, the root signed until {@code policyNotAfter}, and
     * the keyring re-signed until then too. Throws {@link IllegalArgumentException}, having written nothing, when
     * the paths file is malformed, the keyring is missing, does not verify under the key it names or that key is
     * not this policy key, or a requested certificate's service is not in the keyring.
     */
    public static void run(Path pathsYaml, Path keysDir, Path outDir, int depth, long policyNotAfter,
            String replyCertSvc, long replyCertNotAfter) throws IOException {
        List<List<String>> routes = PathsReader.parse(Files.readAllBytes(pathsYaml));
        PrivateKey policyKey = KeyFiles.loadPrivateKey(keysDir.resolve("policy.key"));
        Path keyringFile = keysDir.resolve("keyring.json");
        KeyringFile ring = renewedKeyring(keyringFile, policyNotAfter, policyKey);
        ReplyCert cert = replyCertSvc == null ? null
                : issueReplyCert(keyringFile, ring, replyCertSvc, replyCertNotAfter, policyKey);

        // Signing vouches that every route in paths.yaml is allowed until policyNotAfter: the file is the policy
        // owner's statement of the routes it allows now. The tool cannot check that; the owner keeps the file true.
        PolicyBuilder.Result result = PolicyBuilder.build(routes, depth, policyNotAfter, policyKey);

        writeKeyringInPlace(keyringFile, ring);
        Files.createDirectories(outDir);
        MAPPER.writeValue(outDir.resolve("root.json").toFile(), result.signedRoot());
        for (ProofBundle bundle : result.bundles().values()) {
            MAPPER.writeValue(outDir.resolve("proofs-" + bundle.service() + ".json").toFile(), bundle);
        }
        if (cert != null) {
            MAPPER.writeValue(outDir.resolve("reply-cert.json").toFile(), MAPPER.readTree(cert.toJson()));
        }
    }

    /**
     * Renews: {@code outDir/root.json} and {@code keysDir/keyring.json} signed again until {@code policyNotAfter},
     * each keeping what it lists (the root its {@code root} and {@code rootId}, so the bundles in {@code outDir}
     * still prove against it and are left alone), and, when {@code replyCertSvc} is not null, the certificate
     * reissued until {@code replyCertNotAfter}. Either file may have expired: renewing is how lapsed material comes
     * back. Throws {@link IllegalArgumentException}, having written nothing, when either is missing or malformed (a
     * root or keyring without {@code notAfter} included), the keyring does not verify under the key it names or that
     * key is not this policy key, the root does not verify under it, or a requested certificate's service is not in
     * the keyring.
     */
    public static void renew(Path keysDir, Path outDir, long policyNotAfter, String replyCertSvc,
            long replyCertNotAfter) throws IOException {
        PrivateKey policyKey = KeyFiles.loadPrivateKey(keysDir.resolve("policy.key"));
        Path keyringFile = keysDir.resolve("keyring.json");
        Path rootFile = outDir.resolve("root.json");
        KeyringFile ring = renewedKeyring(keyringFile, policyNotAfter, policyKey);
        SignedRoot root;
        try {
            root = SignedRoot.load(rootFile);
        } catch (UncheckedIOException | IllegalArgumentException e) {
            throw new IllegalArgumentException(rootFile + " is missing or not a signed root", e);
        }
        ReplyCert cert = replyCertSvc == null ? null
                : issueReplyCert(keyringFile, ring, replyCertSvc, replyCertNotAfter, policyKey);

        // Renewing vouches that every route in the existing tree is still allowed until policyNotAfter. The tool
        // checks only that this policy key signed the tree before; that the owner still allows all of it is the
        // owner's to know. A narrowed policy is a rebuild, never a renewal.
        SignedRoot renewed;
        try {
            renewed = PolicyOwner.renewRoot(root, ring.policy(), policyNotAfter, policyKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(rootFile + ": " + e.getMessage(), e);
        }

        writeKeyringInPlace(keyringFile, ring);
        MAPPER.writeValue(rootFile.toFile(), renewed);
        if (cert != null) {
            MAPPER.writeValue(outDir.resolve("reply-cert.json").toFile(), MAPPER.readTree(cert.toJson()));
        }
    }

    /**
     * The keyring read from {@code keyringFile} and re-signed until {@code notAfter} by core's
     * {@link PolicyOwner#renewKeyring}, which holds the checks re-signing rests on. A refusal names the file.
     */
    private static KeyringFile renewedKeyring(Path keyringFile, long notAfter, PrivateKey policyKey) {
        KeyringFile ring;
        try {
            ring = KeyringFile.load(keyringFile);
        } catch (UncheckedIOException | IllegalArgumentException e) {
            throw new IllegalArgumentException(keyringFile + " is missing or not a keyring", e);
        }
        try {
            return PolicyOwner.renewKeyring(ring, notAfter, policyKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(keyringFile + ": " + e.getMessage(), e);
        }
    }

    /**
     * Writes the keyring over the existing file in place, truncating it, rather than writing a new file and
     * renaming it over the old: the keyring may be a single file mounted into the tool, and a rename onto such a
     * mount fails. It is serialised first, so a failure there leaves the file as it was; a failure during the write
     * itself (a crash, a full disk) leaves it empty or truncated, which the next run refuses, and the way back is new
     * keys from the keygen, since this tool only re-signs a keyring.
     */
    private static void writeKeyringInPlace(Path keyringFile, KeyringFile ring) throws IOException {
        byte[] bytes = MAPPER.writeValueAsBytes(ring);
        try {
            Files.write(keyringFile, bytes);
        } catch (IOException e) {
            throw new CannotWrite(keyringFile, e);
        }
    }

    /**
     * The keyring could not be written. It is the first file either mode writes, after every check has passed, so
     * this is where a keyring mounted read-only into the tool shows up, with nothing yet written; the message says
     * so in one line rather than a stack trace, with the reason the file system gave rather than a guess, since a
     * full disk or a missing permission needs a different fix. An I/O error, not a refusal, so it exits 1.
     */
    static final class CannotWrite extends IOException {
        CannotWrite(Path file, IOException cause) {
            super("cannot write " + file + ": " + reason(cause), cause);
        }

        /**
         * The cause in a few words. Java names some causes only by their type, with the path as the message, so
         * those are spelt out, and any other with no reason is named by its type, never by the path again.
         */
        private static String reason(IOException e) {
            if (e instanceof FileSystemException fs) {
                if (fs.getReason() != null) {
                    return fs.getReason();
                }
                if (fs instanceof AccessDeniedException) {
                    return "Permission denied";
                }
                if (fs instanceof NoSuchFileException) {
                    return "No such file or directory";
                }
                return fs.getClass().getSimpleName();
            }
            return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        }
    }

    /** The certificate from core's {@link PolicyOwner#issueReplyCert}; a refusal names the keyring file. */
    private static ReplyCert issueReplyCert(Path keyringFile, KeyringFile ring, String svc, long notAfter,
            PrivateKey policyKey) {
        try {
            return PolicyOwner.issueReplyCert(ring, svc, notAfter, policyKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(keyringFile + ": " + e.getMessage(), e);
        }
    }

    /** The reply certificate's {@code notAfter}: see {@link #daysFromNow}. */
    static long replyCertNotAfter(String days, long nowMs) {
        return daysFromNow("PAZTPORT_REPLY_CERT_DAYS", days, nowMs);
    }

    /** The root's and keyring's {@code notAfter}: see {@link #daysFromNow}. */
    static long policyNotAfter(String days, long nowMs) {
        return daysFromNow("PAZTPORT_POLICY_DAYS", days, nowMs);
    }

    /**
     * Now plus {@code days} days (default 7 when null). Refuses anything but a positive whole number of days, and a
     * lifetime that would end past 2^53 &minus; 1 ms, which nothing this tool signs can carry.
     */
    private static long daysFromNow(String setting, String days, long nowMs) {
        long d;
        try {
            d = days == null ? DEFAULT_DAYS : Integer.parseInt(days);
        } catch (NumberFormatException e) {
            d = 0;
        }
        if (d < 1 || d > (SignedRoot.MAX_NOT_AFTER - nowMs) / DAY_MS) {
            throw new IllegalArgumentException(setting + " must be a positive whole number of days"
                    + " ending before 2^53 - 1 ms");
        }
        return nowMs + d * DAY_MS;
    }

    /** Parsed command line: the three paths, defaulted, and whether to renew. */
    record Args(Path pathsYaml, Path keysDir, Path outDir, boolean renew) {
    }

    /**
     * Positional paths with {@code --renew} anywhere among them; {@code renewEnv} is {@code PAZTPORT_RENEW}, which
     * also asks for renewal when {@code true}, so the same command line serves both modes. Any other flag, or any
     * other value of the variable but {@code false} or empty, is refused.
     */
    static Args parse(String[] args, String renewEnv) {
        boolean renew = false;
        List<String> positional = new ArrayList<>();
        for (String a : args) {
            if (a.equals("--renew")) {
                renew = true;
            } else if (a.startsWith("--")) {
                throw new IllegalArgumentException("unknown option " + a);
            } else {
                positional.add(a);
            }
        }
        if (positional.size() > 3) {
            throw new IllegalArgumentException("at most three paths");
        }
        if (renewEnv != null && !renewEnv.isEmpty()) {
            if (renewEnv.equals("true")) {
                renew = true;
            } else if (!renewEnv.equals("false")) {
                throw new IllegalArgumentException("PAZTPORT_RENEW must be true or false");
            }
        }
        return new Args(Path.of(positional.size() > 0 ? positional.get(0) : "policy/paths.yaml"),
                Path.of(positional.size() > 1 ? positional.get(1) : "out/keys"),
                Path.of(positional.size() > 2 ? positional.get(2) : "out/policy"), renew);
    }

    public static void main(String[] args) throws IOException {
        String replyCertSvc = System.getenv("PAZTPORT_REPLY_CERT_SVC");
        Args a;
        long policyNotAfter;
        long certNotAfter = 0;
        int depth;
        try {
            a = parse(args, System.getenv("PAZTPORT_RENEW"));
            long now = System.currentTimeMillis();
            policyNotAfter = policyNotAfter(System.getenv("PAZTPORT_POLICY_DAYS"), now);
            if (replyCertSvc != null) {
                certNotAfter = replyCertNotAfter(System.getenv("PAZTPORT_REPLY_CERT_DAYS"), now);
            }
            depth = Integer.parseInt(System.getenv().getOrDefault("PAZTPORT_PROOF_DEPTH", "8"));
        } catch (IllegalArgumentException e) {
            System.err.println("policy-tool: " + e.getMessage());
            System.err.println("usage: policy-tool [--renew] [paths.yaml] [keysDir] [outDir]");
            System.exit(2);
            return;
        }
        try {
            if (a.renew()) {
                renew(a.keysDir(), a.outDir(), policyNotAfter, replyCertSvc, certNotAfter);
            } else {
                run(a.pathsYaml(), a.keysDir(), a.outDir(), depth, policyNotAfter, replyCertSvc, certNotAfter);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("policy-tool: refused: " + e.getMessage());
            System.exit(2);
            return;
        } catch (CannotWrite e) {
            System.err.println("policy-tool: " + e.getMessage());
            System.exit(1);
            return;
        }

        String when = "notAfter " + policyNotAfter + " (" + Instant.ofEpochMilli(policyNotAfter) + ")";
        if (a.renew()) {
            System.out.println("policy-tool: renewed " + a.outDir().resolve("root.json") + " and "
                    + a.keysDir().resolve("keyring.json") + ", " + when + "; proof bundles in " + a.outDir()
                    + " unchanged");
        } else {
            System.out.println("policy-tool: wrote " + a.outDir().resolve("root.json") + " and "
                    + a.keysDir().resolve("keyring.json") + ", " + when + ", and per-service bundles to "
                    + a.outDir());
        }
        if (replyCertSvc != null) {
            System.out.println("policy-tool: wrote " + a.outDir().resolve("reply-cert.json") + " for " + replyCertSvc
                    + ", notAfter " + certNotAfter + " (" + Instant.ofEpochMilli(certNotAfter) + ")");
        }
    }
}
