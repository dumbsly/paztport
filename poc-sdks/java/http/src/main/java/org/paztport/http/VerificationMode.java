// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

/**
 * How a verifying service treats a request. {@link #AUDIT} and {@link #ENFORCE} are the protocol's two modes;
 * {@link #OFF} is not a protocol mode but this SDK's deployment switch, kept so that an operator can take Paztport
 * off a hop and measure against it.
 */
public enum VerificationMode {

    /**
     * Not a protocol mode: this hop is not running Paztport. No verification, no response attestation and no events;
     * everything passes (the latency baseline). Its callers count its responses as {@code local-untrusted}, so
     * switching a hop off can only add caution downstream.
     */
    OFF,

    /**
     * Run every check, refuse nothing and report the result: publish an event, marked audit, for each failure, and
     * pass the request through. Influence that cannot be read is still answered 400, since it may not be dropped.
     */
    AUDIT,

    /** Verify, publish an event and refuse on failure. */
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
