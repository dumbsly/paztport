// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.boundary;

import java.time.Duration;

/**
 * Test access to the read timeout a {@link BoundaryClient} was built with, which it keeps package-private. The
 * starter's tests check that {@code paztport.read-timeout-ms} reaches the egress, so this lives in the client's
 * package for that reason only.
 */
public final class BoundaryAccess {

    private BoundaryAccess() {
    }

    /** The read timeout each of {@code client}'s calls has. */
    public static Duration readTimeout(BoundaryClient client) {
        return client.readTimeout();
    }
}
