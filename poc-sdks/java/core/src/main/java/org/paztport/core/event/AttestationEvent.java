// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

/**
 * A verification verdict worth reporting, before it is sent: the {@link ResponderEvent} without the time and id
 * the sender gives it when it signs. {@code audit} marks events produced in audit mode; the responder ignores
 * those.
 */
public record AttestationEvent(
        String reason, String suspectSvc, String suspectInst, String rid, boolean audit) {

    /** The event as the responder reads it, sent at {@code ts} (epoch ms) under the id {@code eventId}. */
    public ResponderEvent sentAt(long ts, String eventId) {
        return new ResponderEvent(reason, suspectSvc, suspectInst, rid, audit, ts, eventId);
    }
}
