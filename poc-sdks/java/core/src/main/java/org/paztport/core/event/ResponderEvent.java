// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import java.util.Set;
import org.paztport.core.internal.Json;

/**
 * The rejection event a verifying service sends to its responder, carried inside a signed
 * envelope. Mirrors the verifier's verdict; {@code ts} (epoch ms) and
 * {@code eventId} let the responder refuse stale and replayed events.
 */
public record ResponderEvent(
        String reason, String suspectSvc, String suspectInst, String rid, boolean audit, long ts, String eventId) {

    /**
     * The reasons that report what the sender did. It is an allow-list because the reason is the signer's text, and
     * a code this SDK does not know must not be acted on. Any other reason is the verifier's own policy running out,
     * a sound chain refused for what shaped it, or a code that is never a live verdict.
     */
    private static final Set<String> ATTRIBUTABLE_REASONS = Set.of("CHAIN_MISSING", "BAD_ORIGIN", "BAD_SIGNATURE",
            "BROKEN_LINK", "EXPIRED", "RID_MISMATCH", "BINDING_MISMATCH", "REPLAY", "PATH_NOT_ALLOWED",
            "SESSION_UNKNOWN", "CLIENT_PATH_NOT_ALLOWED", "INFLUENCE_MISMATCH", "PEER_MISMATCH");

    /**
     * Whether a responder may act against the suspect: the event is not an audit measurement, it names both a
     * service and an instance, and its reason is on the fail-closed allow-list of the spec's attributable events.
     */
    public boolean attributable() {
        return !audit && !suspectSvc.isEmpty() && !suspectInst.isEmpty() && ATTRIBUTABLE_REASONS.contains(reason);
    }

    /**
     * The event's JSON, fields in the order the spec lists them, as the bytes {@link EventEnvelope#sign} signs.
     * The responder reads back the bytes it was sent, so this need not be canonical, only one form every sender
     * of this SDK writes.
     */
    public String toJson() {
        return Json.writeText(this);
    }
}
