// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.policy.Keyring;

/**
 * Decides whether an event body may reach whatever acts on it. Anyone on the
 * mesh can POST to the responder, so an event counts only if it is a signed
 * {@link EventEnvelope} from an allowed signer, fresh, and not seen before.
 * Every failure is a typed {@link Refusal} that takes no decision; nothing here
 * throws on hostile input. Core does no logging: the caller decides how to
 * report a refusal, and must treat the signer in an {@link Outcome} as
 * configuration-controlled only for the refusals that carry it.
 *
 * <p>The signature is checked over the payload string as received, and the event
 * is decoded from that same string. An event id is remembered only once the
 * envelope has passed every other check, for twice the freshness window, so a
 * captured event cannot be replayed while its timestamp is still acceptable.
 * Parsing and the signature check run unlocked; only that memory is guarded.
 *
 * <p>The envelope and the event are each read from their bytes as the spec reads every object it defines: wire
 * bytes that are exactly the object's JCS bytes, then its schema, exactly its own members, each of its type. Nothing
 * is coerced or filled in, so an implementation in any language accepts the same bodies, and whatever acts on an
 * accepted event never meets a missing field.
 */
public final class EventVerifier {

    /** The envelope's three members. */
    private static final Set<String> ENVELOPE = Set.of("signer", "payload", "sig");

    /** The event's members but {@code eventId}, which is checked apart; any member but these seven is malformed. */
    private static final Set<String> EVENT = Set.of("reason", "suspectSvc", "suspectInst", "rid", "audit", "ts");

    /** An event's {@code ts} may differ from now by at most this much, either way. */
    static final long WINDOW_MS = 30_000;

    /** Why a body was refused. */
    public enum Refusal {
        MALFORMED_ENVELOPE,
        SIGNER_NOT_ALLOWED,
        /** Allowed by configuration but absent from every keyring. */
        UNKNOWN_SIGNER,
        BAD_SIGNATURE,
        MALFORMED_EVENT,
        NO_EVENT_ID,
        OUTSIDE_WINDOW,
        REPEATED_EVENT_ID
    }

    /**
     * Either the verified event or a refusal. {@code signer} is set only for
     * {@link Refusal#UNKNOWN_SIGNER} and {@link Refusal#BAD_SIGNATURE}, where
     * it has already passed the allow-list; it is null otherwise, since a
     * disallowed signer is attacker-chosen text.
     */
    public record Outcome(ResponderEvent event, Refusal refusal, String signer) {

        public boolean accepted() {
            return event != null;
        }
    }

    private final List<Keyring> keyrings;
    private final Set<String> allowedSigners;
    private final LongSupplier clock;
    private final Map<String, Long> seen = new HashMap<>();

    /**
     * A verifier taking events from {@code allowedSigners}, each signed under a key one of {@code keyrings} gives it
     * by its own name. The keyrings carry no windows: they are the responder's own configuration, trusted as given.
     * Throws for no keyrings or a null one, so no event meets either.
     */
    public EventVerifier(List<Keyring> keyrings, Set<String> allowedSigners, LongSupplier clock) {
        this.keyrings = ChainChecks.members(keyrings, "keyrings");
        this.allowedSigners = Set.copyOf(allowedSigners);
        this.clock = clock;
    }

    /** The verified event, or the reason the body must be refused. */
    public Outcome accept(String body) {
        EventEnvelope envelope = envelope(body);
        if (envelope == null) {
            return refuse(Refusal.MALFORMED_ENVELOPE, null);
        }
        if (!allowedSigners.contains(envelope.signer())) {
            return refuse(Refusal.SIGNER_NOT_ALLOWED, null);
        }
        List<PublicKey> keys = ChainChecks.keysFor(keyrings, envelope.signer());
        if (keys.isEmpty()) {
            return refuse(Refusal.UNKNOWN_SIGNER, envelope.signer());
        }
        if (keys.stream().noneMatch(envelope::verifiesWith)) {
            return refuse(Refusal.BAD_SIGNATURE, envelope.signer());
        }
        ResponderEvent event = event(envelope.payloadBytes());
        if (event == null) {
            return refuse(Refusal.MALFORMED_EVENT, null);
        }
        if (event.eventId() == null || event.eventId().isEmpty()) {
            return refuse(Refusal.NO_EVENT_ID, null);
        }

        long now = clock.getAsLong();
        if (!withinWindow(now, event.ts())) {
            return refuse(Refusal.OUTSIDE_WINDOW, null);
        }
        if (!firstSighting(event.eventId(), now)) {
            return refuse(Refusal.REPEATED_EVENT_ID, null);
        }
        return new Outcome(event, null, null);
    }

    /**
     * The envelope in {@code body}, or null unless the body's UTF-8 is exactly the JCS bytes of an object whose
     * {@code signer}, {@code payload} and {@code sig} are strings and which has no other member. A body holding a
     * lone surrogate has no UTF-8 form, and is null.
     */
    private static EventEnvelope envelope(String body) {
        if (body == null) {
            return null;
        }
        try {
            JsonValue.Obj o = JsonFields.object(JsonReader.wireText(body));
            JsonFields.exactly(o, ENVELOPE, Set.of());
            return new EventEnvelope(JsonFields.string(o, "signer"), JsonFields.string(o, "payload"),
                    JsonFields.string(o, "sig"));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The event in the payload's bytes, or null unless they are exactly the JCS bytes of an object with the
     * event's members, each of its type, and no other. {@code eventId} may be absent or null, and is then null in
     * the event, which the caller refuses as a missing id rather than a malformed event; when present otherwise it
     * must be a string.
     */
    private static ResponderEvent event(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            JsonValue.Obj o = JsonFields.object(JsonReader.wire(bytes));
            JsonFields.exactly(o, EVENT, Set.of("eventId"));
            JsonValue id = o.get("eventId");
            String eventId = id == null || id instanceof JsonValue.Null ? null : JsonFields.string(o, "eventId");
            return new ResponderEvent(JsonFields.string(o, "reason"), JsonFields.string(o, "suspectSvc"),
                    JsonFields.string(o, "suspectInst"), JsonFields.string(o, "rid"), JsonFields.bool(o, "audit"),
                    JsonFields.integer(o, "ts"), eventId);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Whether {@code ts} is at most {@link #WINDOW_MS} from {@code now}, for any
     * two longs. {@code Math.abs(now - ts)} wraps for extreme values (and
     * {@code Math.abs(Long.MIN_VALUE)} is negative); the larger minus the smaller
     * always fits in an unsigned long, so it is compared unsigned.
     */
    static boolean withinWindow(long now, long ts) {
        long gap = ts >= now ? ts - now : now - ts;
        return Long.compareUnsigned(gap, WINDOW_MS) <= 0;
    }

    /** Remembers {@code eventId}; false if it was already remembered. Only this touches {@link #seen}. */
    private synchronized boolean firstSighting(String eventId, long now) {
        seen.values().removeIf(receivedAt -> now - receivedAt > 2 * WINDOW_MS);
        return seen.putIfAbsent(eventId, now) == null;
    }

    private static Outcome refuse(Refusal why, String signer) {
        return new Outcome(null, why, signer);
    }
}
