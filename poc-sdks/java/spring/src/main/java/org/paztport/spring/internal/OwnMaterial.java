// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import java.nio.file.Path;
import java.util.List;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.OwnMaterial.Kind;
import org.paztport.core.policy.OwnMaterial.Problem;
import org.paztport.core.policy.OwnMaterial.Subject;
import org.paztport.core.policy.SignedRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The startup check every bean that loads {@code paztport.keyring-path} and {@code paztport.root-path} runs on them,
 * so that one place decides what a service may start with, and the message always names the property at fault and
 * the fix. The checks themselves are core's, {@link org.paztport.core.policy.OwnMaterial}; this words their findings
 * in terms of the {@code paztport.*} properties.
 *
 * <p>It refuses, rather than degrades, because a service that loads its own material already expired is
 * misconfigured: nothing about it can be trusted to improve while it runs, and the operator is at the keyboard to
 * re-sign it. A partner whose material expires <em>while running</em> is the other case and does degrade, to unsafe
 * sessions ({@link org.paztport.http.PartnerSessions}), because stopping would cut off the callers it serves without
 * attestation too. The same refusal is what lets {@link org.paztport.core.session.Sessions#status} judge only the
 * windows of the partner's own keyring and root: this check has already made sure both verify under the policy pin.
 *
 * <p>Material that is still current but close to its end is warned about, once, at startup, since a service is
 * restarted far more rarely than a week goes by and this is the last moment the operator is certain to be looking.
 */
public final class OwnMaterial {

    /** A warning is logged when no more than this remains: a quarter of the default lifetime, 42 hours. */
    public static final long WARN_WITHIN_MS = org.paztport.core.policy.OwnMaterial.WARN_WITHIN_MS;

    private static final Logger LOG = LoggerFactory.getLogger(OwnMaterial.class);

    private static final String FIX = "re-sign with the policy tool (PAZTPORT_RENEW=true renews it without rebuilding)";

    private static final String KEYRING = "paztport.keyring-path";
    private static final String ROOT = "paztport.root-path";

    private OwnMaterial() {
    }

    /**
     * Reads {@code paztport.keyring-path}. A file that does not read as a keyring is refused with
     * {@link IllegalStateException} naming the property, the reader's reason and the file, and without the reader's
     * exception under it; one that cannot be read at all throws as {@link KeyringFile#load} does.
     */
    public static KeyringFile loadKeyring(Path file) {
        try {
            return KeyringFile.load(file);
        } catch (IllegalArgumentException e) {
            throw malformed(KEYRING, e, file);
        }
    }

    /** Reads {@code paztport.root-path}, refusing a file that does not read as a root as {@link #loadKeyring} does. */
    public static SignedRoot loadRoot(Path file) {
        try {
            return SignedRoot.load(file);
        } catch (IllegalArgumentException e) {
            throw malformed(ROOT, e, file);
        }
    }

    /** The reader's message names the rule or the member, never the file's text, so it is safe to log. */
    private static IllegalStateException malformed(String property, IllegalArgumentException e, Path file) {
        return new IllegalStateException(property + " is malformed (" + e.getMessage() + "): " + file);
    }

    /**
     * Refuses unless {@code keyring} and {@code root} both verify under {@code policyPin} and are current at
     * {@code nowMs}, throwing {@link IllegalStateException} that names the property and the fix; then warns once for
     * each that has {@link #WARN_WITHIN_MS} or less left. Never prints key material.
     */
    public static void require(KeyringFile keyring, Path keyringFile, SignedRoot root, Path rootFile, String policyPin,
            long nowMs) {
        List<Problem> problems = org.paztport.core.policy.OwnMaterial.check(keyring, root, policyPin, nowMs);
        List<Subject> soon = org.paztport.core.policy.OwnMaterial.expiringSoon(keyring, root, nowMs);
        // A file's warning is logged as its own window is checked, which comes after both signatures and before the
        // other file's window, so a refusal over a later check still leaves the earlier file's warning behind it.
        for (Subject subject : soon) {
            if (problems.isEmpty() || rank(problems.get(0)) > windowRank(subject)) {
                boolean isKeyring = subject == Subject.KEYRING;
                long notAfter = isKeyring ? keyring.notAfter() : root.notAfter();
                LOG.warn("{} {} expires soon, its notAfter {}; {} before then", isKeyring ? KEYRING : ROOT,
                        isKeyring ? keyringFile : rootFile, describe(notAfter), FIX);
            }
        }
        if (!problems.isEmpty()) {
            throw new IllegalStateException(message(problems.get(0), keyringFile, rootFile));
        }
    }

    /** The integer, then its instant when there is one, so that no value however large makes the message throw. */
    public static String describe(long notAfter) {
        return org.paztport.core.policy.OwnMaterial.describe(notAfter);
    }

    private static String message(Problem problem, Path keyringFile, Path rootFile) {
        boolean isKeyring = problem.subject() == Subject.KEYRING;
        String property = isKeyring ? KEYRING : ROOT;
        Path file = isKeyring ? keyringFile : rootFile;
        return switch (problem.kind()) {
            case DOES_NOT_VERIFY -> property + " does not verify under paztport.policy-key-path";
            case EXPIRED -> property + " has expired, its notAfter " + describe(problem.notAfter())
                    + " being past now: " + FIX + ": " + file;
        };
    }

    /** Where a problem falls in core's order: the keyring's signature, the root's, the keyring's window, the root's. */
    private static int rank(Problem problem) {
        boolean isKeyring = problem.subject() == Subject.KEYRING;
        if (problem.kind() == Kind.DOES_NOT_VERIFY) {
            return isKeyring ? 0 : 1;
        }
        return isKeyring ? 2 : 3;
    }

    private static int windowRank(Subject subject) {
        return subject == Subject.KEYRING ? 2 : 3;
    }
}
