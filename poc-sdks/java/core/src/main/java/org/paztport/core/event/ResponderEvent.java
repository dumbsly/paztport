// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

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
     * service and an instance, and its reason is on the fail-closed allow-list of the spec's attributable events. A
     * missing field is not attributable.
     */
    public boolean attributable() {
        return !audit && suspectSvc != null && !suspectSvc.isEmpty() && suspectInst != null && !suspectInst.isEmpty()
                && reason != null && ATTRIBUTABLE_REASONS.contains(reason);
    }

    /**
     * The event's JCS text, its members in JCS order: the bytes {@link EventEnvelope#sign} signs, and the only bytes
     * a responder reads as this event. Throws {@link IllegalArgumentException} for a {@code ts} outside
     * [0, 2^53 &minus; 1], which no responder reads.
     */
    public String toJson() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("reason", new JsonValue.Str(reason));
        o.put("suspectSvc", new JsonValue.Str(suspectSvc));
        o.put("suspectInst", new JsonValue.Str(suspectInst));
        o.put("rid", new JsonValue.Str(rid));
        o.put("audit", new JsonValue.Bool(audit));
        o.put("ts", new JsonValue.Int(ts));
        o.put("eventId", new JsonValue.Str(eventId));
        return JsonWriter.text(new JsonValue.Obj(o));
    }
}
