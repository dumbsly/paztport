// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;

class EventVerifierTest {

    private static final long NOW = 1_000_000L;

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair search = Crypto.generateEd25519KeyPair();
    private final AtomicLong clock = new AtomicLong(NOW);
    private final EventVerifier auth = new EventVerifier(
            Keyring.of(Map.of("payment", payment.getPublic(), "search", search.getPublic())),
            Set.of("payment"), clock::get);

    /** An event's JCS text, with {@code ts} written as given. */
    private static String eventJson(String ts, String eventId) {
        return "{\"audit\":false,\"eventId\":\"" + eventId + "\",\"reason\":\"PATH_NOT_ALLOWED\",\"rid\":\"r\","
                + "\"suspectInst\":\"s1\",\"suspectSvc\":\"search\",\"ts\":" + ts + "}";
    }

    private static String eventJson(long ts, String eventId) {
        return eventJson(Long.toString(ts), eventId);
    }

    private static EventEnvelope signed(String signer, KeyPair key, String json) {
        return EventEnvelope.sign(signer, json.getBytes(StandardCharsets.UTF_8), key.getPrivate());
    }

    private static String envelope(String signer, KeyPair key, String json) {
        return signed(signer, key, json).toJson();
    }

    private Optional<ResponderEvent> accept(String body) {
        return Optional.ofNullable(auth.accept(body).event());
    }

    private EventVerifier.Refusal refusal(String body) {
        return auth.accept(body).refusal();
    }

    @Test
    void acceptsAFreshCorrectlySignedEvent() {
        Optional<ResponderEvent> got = accept(envelope("payment", payment, eventJson(NOW, "a")));
        assertEquals(Optional.of(new ResponderEvent("PATH_NOT_ALLOWED", "search", "s1", "r", false, NOW, "a")), got);
    }

    @Test
    void refusesAnUnsignedPlainEvent() {
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal(eventJson(NOW, "a")));
    }

    @Test
    void refusesGarbageAndNull() {
        assertTrue(accept("not json").isEmpty());
        assertTrue(accept("{}").isEmpty());
        assertTrue(accept(null).isEmpty());
        assertTrue(accept("{\"payload\":\"!!\",\"sig\":\"!!\",\"signer\":\"payment\"}").isEmpty());
    }

    @Test
    void refusesAnUnknownSigner() {
        assertTrue(accept(envelope("ghost", payment, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesAKnownButDisallowedSigner() {
        assertTrue(accept(envelope("search", search, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesASignerClaimingAnotherServicesName() {
        // signed by search's key but labelled payment
        assertTrue(accept(envelope("payment", search, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesATamperedPayload() {
        EventEnvelope good = signed("payment", payment, eventJson(NOW, "a"));
        EventEnvelope forged = signed("payment", payment, eventJson(NOW, "b"));
        assertTrue(accept(new EventEnvelope("payment", forged.payload(), good.sig()).toJson()).isEmpty());
    }

    @Test
    void refusesASignatureWithoutTheDomainPrefix() {
        String payload = Base64Url.encode(eventJson(NOW, "a").getBytes(StandardCharsets.UTF_8));
        String sig = Base64Url.encode(Crypto.sign(payment.getPrivate(), payload.getBytes(StandardCharsets.UTF_8)));
        assertTrue(accept(new EventEnvelope("payment", payload, sig).toJson()).isEmpty());
    }

    @Test
    void refusesAStaleEventAndAFutureEvent() {
        assertTrue(accept(envelope("payment", payment, eventJson(NOW - 30_001, "a"))).isEmpty());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 30_001, "b"))).isEmpty());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW - 30_000, "c"))).isPresent());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 30_000, "d"))).isPresent());
    }

    @Test
    void aTimestampPastTwoToTheFiftyThreeIsMalformed() {
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                refusal(envelope("payment", payment, eventJson(Long.MIN_VALUE, "a"))));
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                refusal(envelope("payment", payment, eventJson(Long.MAX_VALUE, "b"))));
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                refusal(envelope("payment", payment, eventJson("9007199254740992", "c"))));
    }

    @Test
    void aNegativeTsIsMalformed() {
        for (String ts : new String[] {"-1", "-9007199254740991", "-0"}) {
            assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                    refusal(envelope("payment", payment, eventJson(ts, "a"))), ts);
        }
    }

    /** A {@code ts} is a protocol integer by its text: a fraction or an exponent is malformed whatever its value. */
    @Test
    void aTsWrittenWithAFractionIsMalformed() {
        for (String ts : new String[] {NOW + ".0", NOW + ".5", "9007199254740991.4", "1E6", "1000000e0", "0.1e7",
                "1e999999999", "0e999999999"}) {
            assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                    refusal(envelope("payment", payment, eventJson(ts, "a"))), ts);
        }
    }

    @Test
    void aTimestampWhoseDifferenceWrapsIsOutsideTheWindow() {
        // ts is read only in [0, 2^53 - 1], but the clock is any long, so either one-sided difference wraps
        long max = (1L << 53) - 1;
        clock.set(Long.MIN_VALUE);
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW, refusal(envelope("payment", payment, eventJson(max, "b"))));
        clock.set(Long.MAX_VALUE);
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW, refusal(envelope("payment", payment, eventJson(0, "c"))));
        // and the unsigned comparison holds where Math.abs would not: NOW - ts is Long.MIN_VALUE here
        assertFalse(EventVerifier.withinWindow(NOW, NOW + Long.MIN_VALUE));
        assertFalse(EventVerifier.withinWindow(Long.MIN_VALUE, Long.MAX_VALUE));
    }

    @Test
    void refusesARepeatedEventId() {
        String body = envelope("payment", payment, eventJson(NOW, "a"));
        assertTrue(accept(body).isPresent());
        assertTrue(accept(body).isEmpty());
        // a fresh signature over a new payload with the same id is still a repeat
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 1, "a"))).isEmpty());
    }

    @Test
    void remembersAnIdForAtLeastTwiceTheWindow() {
        String body = envelope("payment", payment, eventJson(NOW + 30_000, "a"));
        assertTrue(accept(body).isPresent());
        // the signed ts stays acceptable until NOW + 60_000
        clock.set(NOW + 60_000);
        assertTrue(accept(body).isEmpty());
    }

    @Test
    void refusesAMissingOrNullEventId() {
        String noId = "{\"audit\":false,\"reason\":\"X\",\"rid\":\"r\",\"suspectInst\":\"\",\"suspectSvc\":\"\","
                + "\"ts\":" + NOW + "}";
        assertEquals(EventVerifier.Refusal.NO_EVENT_ID, refusal(envelope("payment", payment, noId)));
        assertEquals(EventVerifier.Refusal.NO_EVENT_ID, refusal(envelope("payment", payment,
                noId.replace("\"audit\":false,", "\"audit\":false,\"eventId\":null,"))));
        assertEquals(EventVerifier.Refusal.NO_EVENT_ID, refusal(envelope("payment", payment, eventJson(NOW, ""))));
    }

    @Test
    void refusalDoesNotConsumeTheEventId() {
        // a bad signature must not let an attacker burn an id the real payment will use
        EventEnvelope good = signed("payment", payment, eventJson(NOW, "a"));
        assertTrue(accept(new EventEnvelope("payment", good.payload(), "AAAA").toJson()).isEmpty());
        assertTrue(accept(good.toJson()).isPresent());
    }

    @Test
    void refusalsCarryTheirTypedReason() {
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal("not json"));
        assertEquals(EventVerifier.Refusal.SIGNER_NOT_ALLOWED,
                refusal(envelope("search", search, eventJson(NOW, "a"))));
        assertEquals(EventVerifier.Refusal.BAD_SIGNATURE, refusal(envelope("payment", search, eventJson(NOW, "a"))));
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW,
                refusal(envelope("payment", payment, eventJson(NOW - 30_001, "a"))));
        assertEquals(EventVerifier.Refusal.REPEATED_EVENT_ID, repeat().refusal());
    }

    private EventVerifier.Outcome repeat() {
        String body = envelope("payment", payment, eventJson(NOW, "r"));
        auth.accept(body);
        return auth.accept(body);
    }

    @Test
    void onlyAnAllowedSignersNameTravelsWithTheRefusal() {
        EventVerifier keyless = new EventVerifier(
                Keyring.of(Map.of("search", search.getPublic())), Set.of("payment"), clock::get);
        EventVerifier.Outcome unknown = keyless.accept(envelope("payment", payment, eventJson(NOW, "a")));
        assertEquals(EventVerifier.Refusal.UNKNOWN_SIGNER, unknown.refusal());
        assertEquals("payment", unknown.signer());
        EventVerifier.Outcome disallowed = auth.accept("{\"payload\":\"e30\",\"sig\":\"AAAA\",\"signer\":\"x\\ny\"}");
        assertEquals(EventVerifier.Refusal.SIGNER_NOT_ALLOWED, disallowed.refusal());
        assertNull(disallowed.signer());
    }

    /** An envelope written {@code {signer, payload, sig}}, as a sender writing the spec's field order would. */
    @Test
    void anEnvelopeInWireMemberOrderIsMalformed() {
        EventEnvelope env = signed("payment", payment, eventJson(NOW, "a"));
        String body = "{\"signer\":\"payment\",\"payload\":\"" + env.payload() + "\",\"sig\":\"" + env.sig() + "\"}";
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal(body));
    }

    @Test
    void aPayloadInWireMemberOrderIsMalformedEvent() {
        String json = "{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"search\",\"suspectInst\":\"s1\",\"rid\":\"r\","
                + "\"audit\":false,\"ts\":" + NOW + ",\"eventId\":\"a\"}";
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT, refusal(envelope("payment", payment, json)));
    }

    @Test
    void whitespaceAroundTheBodyIsMalformed() {
        String good = envelope("payment", payment, eventJson(NOW, "a"));
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal(" \n\t" + good + "\r\n "));
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal(good + "\n"));
    }

    @Test
    void whitespaceAroundThePayloadIsMalformedEvent() {
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                refusal(envelope("payment", payment, " \n" + eventJson(NOW, "a") + "\n")));
    }

    /** A lone surrogate has no UTF-8 form, so a body holding one, raw or escaped, is no envelope's bytes. */
    @Test
    void aPayloadWithALoneSurrogateIsMalformed() {
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE,
                refusal("{\"payload\":\"AA\\ud800\",\"sig\":\"AAAA\",\"signer\":\"payment\"}"));
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE,
                refusal("{\"payload\":\"AA\ud800\",\"sig\":\"AAAA\",\"signer\":\"payment\"}"));
    }

    @Test
    void anEnvelopePastTheWireLimitIsMalformed() {
        String big = "{\"payload\":\"" + "A".repeat(256 * 1024) + "\",\"sig\":\"AAAA\",\"signer\":\"payment\"}";
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, refusal(big));
    }
}
