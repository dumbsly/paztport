// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Retains the last request a verifier received, so the demo can replay or mutate
 * a genuinely valid request. A demo harness simulating an on-the-wire capture;
 * not part of the attestation model. Enabled only when {@code paztport.capture=true}.
 */
public final class CaptureStore {

    private final AtomicReference<CapturedRequest> last = new AtomicReference<>();

    public void record(CapturedRequest request) {
        last.set(request);
    }

    public Optional<CapturedRequest> last() {
        return Optional.ofNullable(last.get());
    }
}
