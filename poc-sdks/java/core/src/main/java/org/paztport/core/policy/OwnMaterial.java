// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

/**
 * What a service that loads its own keyring and root may start with. A service whose own material is already
 * expired is misconfigured: nothing about it improves while it runs, and the operator is at the
 * keyboard to re-sign it. So a caller refuses to start on any {@link Problem} rather than degrading. Material that
 * is still current but close to its end is another matter, reported by {@link #expiringSoon}: a service is
 * restarted far more rarely than a week goes by, and start-up is the last moment the operator is certain to be
 * looking.
 *
 * <p>These are the checks only. How a failure is worded, and what is logged, is the caller's, since it knows which
 * settings the files came from.
 */
public final class OwnMaterial {

    /** The lifetime the policy tool gives what it signs unless told otherwise: seven days. */
    static final long DEFAULT_LIFETIME_MS = TimeUnit.DAYS.toMillis(7);

    /** A warning is due when no more than this remains: a quarter of the default lifetime, 42 hours. */
    public static final long WARN_WITHIN_MS = DEFAULT_LIFETIME_MS / 4;

    private OwnMaterial() {
    }

    /** Which of a service's two files a finding is about. */
    public enum Subject {
        KEYRING,
        ROOT
    }

    /** What is wrong with one of them. */
    public enum Kind {
        /** It does not verify under the pinned policy key. */
        DOES_NOT_VERIFY,
        /** Its {@code notAfter} is before now. */
        EXPIRED
    }

    /**
     * One reason not to start.
     *
     * @param notAfter the file's {@code notAfter}, for {@link Kind#EXPIRED}; null otherwise
     */
    public record Problem(Subject subject, Kind kind, Long notAfter) {
    }

    /**
     * Everything wrong with {@code keyring} and {@code root}, in the order a caller should report them: the
     * keyring's signature, the root's, then the keyring's window and the root's. Empty when both verify under
     * {@code policyPin} and are current at {@code nowMs}. The windows are judged even for a
     * file that does not verify, so a caller reports only the first.
     */
    public static List<Problem> check(KeyringFile keyring, SignedRoot root, String policyPin, long nowMs) {
        List<Problem> problems = new ArrayList<>();
        if (!keyring.verifies(policyPin)) {
            problems.add(new Problem(Subject.KEYRING, Kind.DOES_NOT_VERIFY, null));
        }
        if (!rootVerifies(root, policyPin)) {
            problems.add(new Problem(Subject.ROOT, Kind.DOES_NOT_VERIFY, null));
        }
        window(Subject.KEYRING, keyring.notAfter(), nowMs, problems);
        window(Subject.ROOT, root.notAfter(), nowMs, problems);
        return problems;
    }

    /**
     * The files that are current at {@code nowMs} with {@link #WARN_WITHIN_MS} or less left, keyring first. A file
     * that has already expired is a {@link Problem}, not a warning.
     */
    public static List<Subject> expiringSoon(KeyringFile keyring, SignedRoot root, long nowMs) {
        List<Subject> soon = new ArrayList<>();
        if (endsSoon(keyring.notAfter(), nowMs)) {
            soon.add(Subject.KEYRING);
        }
        if (endsSoon(root.notAfter(), nowMs)) {
            soon.add(Subject.ROOT);
        }
        return soon;
    }

    /** The integer, then its instant when there is one, so that no value however large makes a message throw. */
    public static String describe(long notAfter) {
        try {
            return notAfter + " (" + Instant.ofEpochMilli(notAfter) + ")";
        } catch (RuntimeException e) {
            return Long.toString(notAfter);
        }
    }

    private static boolean endsSoon(long notAfter, long nowMs) {
        return nowMs <= notAfter && notAfter - nowMs <= WARN_WITHIN_MS;
    }

    private static boolean rootVerifies(SignedRoot root, String policyPin) {
        try {
            return root.verify(Crypto.decodePublicKey(Base64Url.decode(policyPin)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static void window(Subject subject, long notAfter, long nowMs, List<Problem> problems) {
        if (nowMs > notAfter) {
            problems.add(new Problem(subject, Kind.EXPIRED, notAfter));
        }
    }
}
