// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The startup check every bean that loads {@code paztport.keyring-path} and {@code paztport.root-path} runs on them,
 * so that one place decides what a service may start with, and the message always names the property at fault and
 * the fix.
 *
 * <p>It refuses, rather than degrades, because a service that loads its own material already old-form or expired
 * is misconfigured: nothing about it can be trusted to improve while it runs, and the operator is at the keyboard
 * to re-sign it. A partner whose material expires <em>while running</em> is the other case and does degrade, to
 * unsafe sessions ({@link PartnerSessions}), because stopping would cut off the callers it serves without
 * attestation too. The same refusal is what lets {@link org.paztport.core.session.Sessions#status} judge only the windows of
 * the partner's own keyring and root: this check has already made sure both verify under the policy pin.
 *
 * <p>Material that is still current but close to its end is warned about, once, at startup, since a service is
 * restarted far more rarely than a week goes by and this is the last moment the operator is certain to be looking.
 */
final class OwnMaterial {

    /** The lifetime the policy tool gives what it signs unless told otherwise: seven days. */
    static final long DEFAULT_LIFETIME_MS = TimeUnit.DAYS.toMillis(7);

    /** A warning is logged when no more than this remains: a quarter of the default lifetime, 42 hours. */
    static final long WARN_WITHIN_MS = DEFAULT_LIFETIME_MS / 4;

    private static final Logger LOG = LoggerFactory.getLogger(OwnMaterial.class);

    private static final String FIX = "re-sign with the policy tool (PAZTPORT_RENEW=true renews it without rebuilding)";

    private OwnMaterial() {
    }

    /**
     * Refuses unless {@code keyring} and {@code root} both verify under {@code policyPin}, are in the new form and
     * are current at {@code nowMs}, throwing {@link IllegalStateException} that names the property and the fix;
     * then warns once for each that has {@link #WARN_WITHIN_MS} or less left. Never prints key material.
     */
    static void require(KeyringFile keyring, Path keyringFile, SignedRoot root, Path rootFile, String policyPin,
            long nowMs) {
        if (!keyring.verifies(policyPin)) {
            throw new IllegalStateException("paztport.keyring-path does not verify under paztport.policy-key-path");
        }
        if (!rootVerifies(root, policyPin)) {
            throw new IllegalStateException("paztport.root-path does not verify under paztport.policy-key-path");
        }
        window("paztport.keyring-path", keyringFile, keyring.notAfter(), nowMs);
        window("paztport.root-path", rootFile, root.notAfter(), nowMs);
    }

    private static boolean rootVerifies(SignedRoot root, String policyPin) {
        try {
            return root.verify(Crypto.decodePublicKey(Base64Url.decode(policyPin)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static void window(String property, Path file, Long notAfter, long nowMs) {
        if (notAfter == null) {
            throw new IllegalStateException(property + " is in the old form, with no notAfter: " + FIX + ": " + file);
        }
        if (nowMs > notAfter) {
            throw new IllegalStateException(property + " has expired, its notAfter " + describe(notAfter)
                    + " being past now: " + FIX + ": " + file);
        }
        if (notAfter - nowMs <= WARN_WITHIN_MS) {
            LOG.warn("{} {} expires soon, its notAfter {}; {} before then", property, file, describe(notAfter), FIX);
        }
    }

    /** The integer, then its instant when there is one, so that no value however large makes the message throw. */
    static String describe(long notAfter) {
        try {
            return notAfter + " (" + Instant.ofEpochMilli(notAfter) + ")";
        } catch (RuntimeException e) {
            return Long.toString(notAfter);
        }
    }
}
