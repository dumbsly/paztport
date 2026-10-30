// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import java.time.Duration;
import org.paztport.spring.PaztportProperties;

/**
 * The durations that more than one feature's beans take from {@code paztport.*}, kept in one place so that each
 * feature reads and refuses them alike. It holds no beans and is not for an application to use.
 */
public final class Durations {

    private Durations() {
    }

    /** {@code paztport.read-timeout-ms}, refused unless positive. */
    public static Duration readTimeout(PaztportProperties props) {
        return positiveMs(props.getReadTimeoutMs(), "paztport.read-timeout-ms");
    }

    public static Duration positiveMs(long ms, String property) {
        if (ms <= 0) {
            throw new IllegalStateException(property + " must be positive");
        }
        return Duration.ofMillis(ms);
    }
}
