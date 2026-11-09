// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.concurrent.atomic.AtomicReference;

/** Holds the current verification mode, which an adapter such as the Spring starter can change at runtime. */
public final class ModeHolder {

    private final AtomicReference<VerificationMode> mode;

    public ModeHolder(VerificationMode initial) {
        this.mode = new AtomicReference<>(initial);
    }

    public VerificationMode get() {
        return mode.get();
    }

    public void set(VerificationMode newMode) {
        mode.set(newMode);
    }
}
