// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

/** Whether the service has begun to drain. It starts false and, once set, stays set. */
public final class DrainState {

    private volatile boolean draining;

    /** Starts the drain. */
    public void begin() {
        draining = true;
    }

    /** Returns whether the service is draining. */
    public boolean draining() {
        return draining;
    }
}
