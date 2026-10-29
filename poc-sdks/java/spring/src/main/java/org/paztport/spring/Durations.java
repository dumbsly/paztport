// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.time.Duration;
import org.paztport.core.verify.VerifierConfigV3;

/**
 * The durations that more than one feature's beans take from {@code paztport.*}, kept in one place so that each
 * feature reads and refuses them alike. It holds no beans and is not for an application to use.
 */
final class Durations {

    private Durations() {
    }

    /** {@code paztport.read-timeout-ms}, refused unless positive. */
    static Duration readTimeout(PaztportProperties props) {
        return positiveMs(props.getReadTimeoutMs(), "paztport.read-timeout-ms");
    }

    static Duration positiveMs(long ms, String property) {
        if (ms <= 0) {
            throw new IllegalStateException(property + " must be positive");
        }
        return Duration.ofMillis(ms);
    }

    /** The verifier refuses a cache that forgets sooner than twice the call window, so this never goes below it. */
    static long nonceTtlMs(long maxAgeMs) {
        return Math.max(VerifierConfigV3.NONCE_TTL_MS, 2 * maxAgeMs);
    }
}
