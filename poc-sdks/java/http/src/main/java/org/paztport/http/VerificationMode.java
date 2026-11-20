// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.Locale;

/**
 * How a verifying service treats a request. {@link #AUDIT} and {@link #ENFORCE} are the protocol's two modes;
 * {@link #OFF} is not a protocol mode but this SDK's deployment switch, kept so that an operator can take Paztport
 * off a hop and measure against it.
 */
public enum VerificationMode {

    /**
     * Not a protocol mode: this hop is not running Paztport. No verification, no response attestation and no events,
     * so verification refuses nothing (the latency baseline). Blocks that cannot be carried, and influence or intent
     * that cannot be read, are still answered 400, since they may not be dropped. A request is handed no verified
     * facts, so a handler that requires the origin's facts refuses it {@code 403 INTENT_MISSING}. Its callers count
     * its responses as {@code local-untrusted}, so switching a hop off can only add caution downstream.
     */
    OFF,

    /**
     * Run every check, refuse nothing and report the result: publish an event, marked audit, for each failure, and
     * pass the request through. Influence or intent that cannot be read is still answered 400, since it may not be
     * dropped. A request passed through after a failure is handed no verified facts, so a handler that requires the
     * origin's facts still refuses it {@code 403 INTENT_MISSING}.
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
            return VerificationMode.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return ENFORCE;
        }
    }
}
