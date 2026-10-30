// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.boundary;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * The egress's package-private hooks, for the root package's tests, which sit outside {@code boundary}: the clocks
 * and the handshake timeout a test moves by hand, and the two constants it measures them against. The test jar leaves
 * this out, so nothing outside this module's tests can reach the hooks.
 */
public final class BoundaryHooks {

    /** The refusal's message when the request's context holds no chain that verified here. */
    public static final String NO_VERIFIED_CHAIN = "no verified chain: nothing is signed at the boundary";

    /** How long a replacement session is kept before the partner is asked for an attested one again. */
    public static final Duration FALLBACK_PERIOD = Duration.ofSeconds(30);

    private BoundaryHooks() {
    }

    /** {@code b} with its monotonic clock, in nanoseconds, replaced by {@code nanos}. */
    public static BoundaryClient.Builder nanos(BoundaryClient.Builder b, LongSupplier nanos) {
        return b.nanos(nanos);
    }

    /** {@code b} with its time of day, in milliseconds since the epoch, replaced by {@code millis}. */
    public static BoundaryClient.Builder millis(BoundaryClient.Builder b, LongSupplier millis) {
        return b.millis(millis);
    }

    /** {@code b} with the time a handshake may take replaced by {@code timeout}. */
    public static BoundaryClient.Builder handshakeTimeout(BoundaryClient.Builder b, Duration timeout) {
        return b.handshakeTimeout(timeout);
    }
}
