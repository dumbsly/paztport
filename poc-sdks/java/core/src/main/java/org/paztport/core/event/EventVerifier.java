// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.internal.Json;
import org.paztport.core.internal.JsonIntegers;
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
 * <p>The envelope and the event are read strictly, as the spec defines them: exactly one JSON object each, with
 * exactly their own members, each of its JSON type, and the payload in strict UTF-8. Nothing is coerced or filled
 * in, so an implementation in any language accepts the same bodies, and whatever acts on an accepted event never
 * meets a missing field.
 */
public final class EventVerifier {

    /** The event's seven members; any other is malformed. */
    private static final Set<String> MEMBERS =
            Set.of("reason", "suspectSvc", "suspectInst", "rid", "audit", "ts", "eventId");

    /** The members that must be present as JSON strings; {@code eventId} is checked apart. */
    private static final Set<String> STRINGS = Set.of("reason", "suspectSvc", "suspectInst", "rid");

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
        EventEnvelope envelope = envelope(body);
        if (envelope == null) {
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
     * The envelope in {@code body}, or null unless it is exactly one JSON object whose {@code signer},
     * {@code payload} and {@code sig} are strings and which has no other member.
     */
    private static EventEnvelope envelope(String body) {
        JsonNode node;
        try {
            node = Json.tree(body);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!node.isObject() || node.size() != 3) {
            return null;
        }
        JsonNode signer = node.get("signer");
        JsonNode payload = node.get("payload");
        JsonNode sig = node.get("sig");
        if (signer == null || !signer.isTextual() || payload == null || !payload.isTextual()
                || sig == null || !sig.isTextual()) {
            return null;
        }
        return new EventEnvelope(signer.asText(), payload.asText(), sig.asText());
    }

    /**
     * The event in the payload's bytes, or null unless they are strict UTF-8 holding exactly one JSON object with
     * the event's members, each of its type, and no other. {@code eventId} may be absent or null, and is then null
     * in the event, which the caller refuses as a missing id rather than a malformed event; when present otherwise
     * it must be a string.
     */
    private static ResponderEvent event(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        JsonNode node;
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
            node = Json.exactTree(text);
        } catch (CharacterCodingException | IllegalArgumentException e) {
            return null;
        }
        if (!node.isObject()) {
            return null;
        }
        for (Iterator<String> names = node.fieldNames(); names.hasNext();) {
            if (!MEMBERS.contains(names.next())) {
                return null;
            }
        }
        for (String name : STRINGS) {
            JsonNode v = node.get(name);
            if (v == null || !v.isTextual()) {
                return null;
            }
        }
        JsonNode audit = node.get("audit");
        Long ts = JsonIntegers.safeInteger(node.get("ts"));
        if (audit == null || !audit.isBoolean() || ts == null) {
            return null;
        }
        JsonNode id = node.get("eventId");
        boolean absent = id == null || id.isNull();
        if (!absent && !id.isTextual()) {
            return null;
        }
        return new ResponderEvent(node.get("reason").asText(), node.get("suspectSvc").asText(),
                node.get("suspectInst").asText(), node.get("rid").asText(), audit.asBoolean(), ts,
                absent ? null : id.asText());
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
