// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.EventEnvelope;
import org.paztport.core.Keyring;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides whether an event body may reach the decider. Anyone on the mesh can
 * POST to the responder, so an event counts only if it is a signed
 * {@link EventEnvelope} from an allowed signer, fresh, and not seen before.
 * Every failure is a refusal (an empty result) that takes no decision; nothing
 * here throws on hostile input.
 *
 * <p>The signature is checked over the payload string as received, and the event
 * is decoded from that same string. An event id is remembered only once the
 * envelope has passed every other check, for twice the freshness window, so a
 * captured event cannot be replayed while its timestamp is still acceptable.
 * Parsing and the signature check run unlocked; only that memory is guarded.
 */
public final class EventAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(EventAuthenticator.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** An event's {@code ts} may differ from now by at most this much, either way. */
    static final long WINDOW_MS = 30_000;

    private final Keyring keyring;
    private final Set<String> allowedSigners;
    private final LongSupplier clock;
    private final Map<String, Long> seen = new HashMap<>();

    public EventAuthenticator(Keyring keyring, Set<String> allowedSigners, LongSupplier clock) {
        this.keyring = keyring;
        this.allowedSigners = Set.copyOf(allowedSigners);
        this.clock = clock;
    }

    /** The verified event, or empty (and a logged reason) if the body must be refused. */
    public Optional<ResponderEvent> accept(String body) {
        EventEnvelope envelope;
        try {
            envelope = JSON.readValue(body, EventEnvelope.class);
        } catch (Exception e) {
            return refuse("malformed envelope");
        }
        if (envelope == null || envelope.signer() == null || envelope.payload() == null || envelope.sig() == null) {
            return refuse("malformed envelope");
        }
        if (!allowedSigners.contains(envelope.signer())) {
            return refuse("signer not allowed");
        }
        PublicKey key = keyring.keyFor(envelope.signer());
        if (key == null) {
            return refuse("unknown signer: " + envelope.signer());
        }
        if (!envelope.verifiesWith(key)) {
            return refuse("bad signature from " + envelope.signer());
        }
        byte[] json = envelope.payloadBytes();
        ResponderEvent event;
        try {
            event = JSON.readValue(new String(json, StandardCharsets.UTF_8), ResponderEvent.class);
        } catch (Exception e) {
            return refuse("malformed event");
        }
        if (event == null || event.eventId() == null || event.eventId().isBlank()) {
            return refuse("event has no id");
        }

        long now = clock.getAsLong();
        if (!withinWindow(now, event.ts())) {
            return refuse("event outside the freshness window");
        }
        if (!firstSighting(event.eventId(), now)) {
            return refuse("repeated event id");
        }
        return Optional.of(event);
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

    private static Optional<ResponderEvent> refuse(String why) {
        log.warn("refused event: {}", why);
        return Optional.empty();
    }
}
