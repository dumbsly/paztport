// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * The rejection event payment sends to the responder, carried inside a signed
 * envelope. Mirrors the verifier's verdict; {@code ts} (epoch ms) and
 * {@code eventId} let the responder refuse stale and replayed events.
 */
public record ResponderEvent(
        String reason, String suspectSvc, String suspectInst, String rid, boolean audit, long ts, String eventId) {
}
