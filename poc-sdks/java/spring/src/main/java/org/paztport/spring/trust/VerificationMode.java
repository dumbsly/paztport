// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

/** How a verifying service treats a request. */
public enum VerificationMode {

    /**
     * Paztport off on this hop: no verification and no response attestation; pass everything (the latency
     * baseline).
     */
    OFF,

    /** Verify and publish events, but always pass the request through. */
    AUDIT,

    /** Verify and reject on failure. */
    ENFORCE;

    /** Parses a property value, failing closed to {@link #ENFORCE} on null, blank, or unknown. */
    public static VerificationMode fromProperty(String value) {
        if (value == null || value.isBlank()) {
            return ENFORCE;
        }
        try {
            return VerificationMode.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ENFORCE;
        }
    }
}
