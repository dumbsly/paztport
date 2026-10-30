// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
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
 */
public final class EventVerifier {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** An event's {@code ts} may differ from now by at most this much, either way. */
    static final long WINDOW_MS = 30_000;

    /** Why a body was refused. */
    public enum Refusal {
        MALFORMED_ENVELOPE,
        SIGNER_NOT_ALLOWED,
        /** Allowed by configuration but absent from the keyring. */
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

    private final Keyring keyring;
    private final Set<String> allowedSigners;
    private final LongSupplier clock;
    private final Map<String, Long> seen = new HashMap<>();

    public EventVerifier(Keyring keyring, Set<String> allowedSigners, LongSupplier clock) {
        this.keyring = keyring;
        this.allowedSigners = Set.copyOf(allowedSigners);
        this.clock = clock;
    }

    /** The verified event, or the reason the body must be refused. */
    public Outcome accept(String body) {
        EventEnvelope envelope;
        try {
            envelope = JSON.readValue(body, EventEnvelope.class);
        } catch (Exception e) {
            return refuse(Refusal.MALFORMED_ENVELOPE, null);
        }
        if (envelope == null || envelope.signer() == null || envelope.payload() == null || envelope.sig() == null) {
            return refuse(Refusal.MALFORMED_ENVELOPE, null);
        }
        if (!allowedSigners.contains(envelope.signer())) {
            return refuse(Refusal.SIGNER_NOT_ALLOWED, null);
        }
        PublicKey key = keyring.keyFor(envelope.signer());
        if (key == null) {
            return refuse(Refusal.UNKNOWN_SIGNER, envelope.signer());
        }
        if (!envelope.verifiesWith(key)) {
            return refuse(Refusal.BAD_SIGNATURE, envelope.signer());
        }
        byte[] json = envelope.payloadBytes();
        if (json == null) {
            return refuse(Refusal.MALFORMED_EVENT, null);
        }
        ResponderEvent event;
        try {
            event = JSON.readValue(new String(json, StandardCharsets.UTF_8), ResponderEvent.class);
        } catch (Exception e) {
            return refuse(Refusal.MALFORMED_EVENT, null);
        }
        if (event == null || event.eventId() == null || event.eventId().isBlank()) {
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
