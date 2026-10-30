// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.Keyring;

class EventVerifierTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long NOW = 1_000_000L;

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair search = Crypto.generateEd25519KeyPair();
    private final AtomicLong clock = new AtomicLong(NOW);
    private final EventVerifier auth = new EventVerifier(
            Keyring.of(Map.of("payment", payment.getPublic(), "search", search.getPublic())),
            Set.of("payment"), clock::get);

    private static String eventJson(long ts, String eventId) {
        return "{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"search\",\"suspectInst\":\"s1\","
                + "\"rid\":\"r\",\"audit\":false,\"ts\":" + ts + ",\"eventId\":\"" + eventId + "\"}";
    }

    private static String envelope(String signer, KeyPair key, String json) throws Exception {
        return JSON.writeValueAsString(
                EventEnvelope.sign(signer, json.getBytes(StandardCharsets.UTF_8), key.getPrivate()));
    }

    private Optional<ResponderEvent> accept(String body) {
        return Optional.ofNullable(auth.accept(body).event());
    }

    @Test
    void acceptsAFreshCorrectlySignedEvent() throws Exception {
        Optional<ResponderEvent> got = accept(envelope("payment", payment, eventJson(NOW, "a")));
        assertTrue(got.isPresent());
        assertEquals("PATH_NOT_ALLOWED", got.get().reason());
        assertEquals("s1", got.get().suspectInst());
    }

    @Test
    void refusesAnUnsignedPlainEvent() {
        assertTrue(accept(eventJson(NOW, "a")).isEmpty());
    }

    @Test
    void refusesGarbageAndNull() {
        assertTrue(accept("not json").isEmpty());
        assertTrue(accept("{}").isEmpty());
        assertTrue(accept(null).isEmpty());
        assertTrue(accept("{\"signer\":\"payment\",\"payload\":\"!!\",\"sig\":\"!!\"}").isEmpty());
    }

    @Test
    void refusesAnUnknownSigner() throws Exception {
        assertTrue(accept(envelope("ghost", payment, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesAKnownButDisallowedSigner() throws Exception {
        assertTrue(accept(envelope("search", search, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesASignerClaimingAnotherServicesName() throws Exception {
        // signed by search's key but labelled payment
        assertTrue(accept(envelope("payment", search, eventJson(NOW, "a"))).isEmpty());
    }

    @Test
    void refusesATamperedPayload() throws Exception {
        EventEnvelope good = EventEnvelope.sign("payment",
                eventJson(NOW, "a").getBytes(StandardCharsets.UTF_8), payment.getPrivate());
        EventEnvelope forged = EventEnvelope.sign("payment",
                eventJson(NOW, "b").getBytes(StandardCharsets.UTF_8), payment.getPrivate());
        String body = JSON.writeValueAsString(new EventEnvelope("payment", forged.payload(), good.sig()));
        assertTrue(accept(body).isEmpty());
    }

    @Test
    void refusesASignatureWithoutTheDomainPrefix() throws Exception {
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(eventJson(NOW, "a").getBytes(StandardCharsets.UTF_8));
        byte[] bare = Crypto.sign(payment.getPrivate(), payload.getBytes(StandardCharsets.UTF_8));
        String sig = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bare);
        assertTrue(accept(JSON.writeValueAsString(new EventEnvelope("payment", payload, sig))).isEmpty());
    }

    @Test
    void refusesAStaleEventAndAFutureEvent() throws Exception {
        assertTrue(accept(envelope("payment", payment, eventJson(NOW - 30_001, "a"))).isEmpty());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 30_001, "b"))).isEmpty());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW - 30_000, "c"))).isPresent());
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 30_000, "d"))).isPresent());
    }

    @Test
    void aTimestampPastTwoToTheFiftyThreeIsMalformed() throws Exception {
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                auth.accept(envelope("payment", payment, eventJson(Long.MIN_VALUE, "a"))).refusal());
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                auth.accept(envelope("payment", payment, eventJson(Long.MAX_VALUE, "b"))).refusal());
    }

    @Test
    void aTimestampIsJudgedByItsWrittenValue() throws Exception {
        // As a double this is 9007199254740991, so only the written text shows it is not an integer.
        for (String ts : new String[] {"9007199254740991.4", NOW + ".00000000000000000001", "1e-999999999"}) {
            String json = eventJson(0, "a").replace("\"ts\":0", "\"ts\":" + ts);
            assertEquals(EventVerifier.Refusal.MALFORMED_EVENT,
                    auth.accept(envelope("payment", payment, json)).refusal(), ts);
        }
        // An exponent too large to build an integer from is refused, not built.
        assertEquals(EventVerifier.Refusal.MALFORMED_EVENT, auth.accept(envelope("payment", payment,
                eventJson(0, "b").replace("\"ts\":0", "\"ts\":1e999999999"))).refusal());
        assertTrue(accept(envelope("payment", payment,
                eventJson(0, "c").replace("\"ts\":0", "\"ts\":1E6"))).isPresent());
    }

    @Test
    void aTimestampWhoseDifferenceWrapsIsOutsideTheWindow() throws Exception {
        // ts is read only within +-(2^53 - 1), but the clock is any long, so either one-sided difference wraps
        long max = (1L << 53) - 1;
        clock.set(Long.MIN_VALUE);
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW,
                auth.accept(envelope("payment", payment, eventJson(max, "b"))).refusal());
        clock.set(Long.MAX_VALUE);
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW,
                auth.accept(envelope("payment", payment, eventJson(-max, "c"))).refusal());
        // and the unsigned comparison holds where Math.abs would not: NOW - ts is Long.MIN_VALUE here
        assertFalse(EventVerifier.withinWindow(NOW, NOW + Long.MIN_VALUE));
        assertFalse(EventVerifier.withinWindow(Long.MIN_VALUE, Long.MAX_VALUE));
    }

    @Test
    void refusesARepeatedEventId() throws Exception {
        String body = envelope("payment", payment, eventJson(NOW, "a"));
        assertTrue(accept(body).isPresent());
        assertTrue(accept(body).isEmpty());
        // a fresh signature over a new payload with the same id is still a repeat
        assertTrue(accept(envelope("payment", payment, eventJson(NOW + 1, "a"))).isEmpty());
    }

    @Test
    void remembersAnIdForAtLeastTwiceTheWindow() throws Exception {
        String body = envelope("payment", payment, eventJson(NOW + 30_000, "a"));
        assertTrue(accept(body).isPresent());
        // the signed ts stays acceptable until NOW + 60_000
        clock.set(NOW + 60_000);
        assertTrue(accept(body).isEmpty());
    }

    @Test
    void refusesAMissingEventId() throws Exception {
        String json = "{\"reason\":\"X\",\"suspectSvc\":\"\",\"suspectInst\":\"\",\"rid\":\"r\","
                + "\"audit\":false,\"ts\":" + NOW + "}";
        assertTrue(accept(envelope("payment", payment, json)).isEmpty());
    }

    @Test
    void refusalDoesNotConsumeTheEventId() throws Exception {
        // a bad signature must not let an attacker burn an id the real payment will use
        EventEnvelope good = EventEnvelope.sign("payment",
                eventJson(NOW, "a").getBytes(StandardCharsets.UTF_8), payment.getPrivate());
        String bad = JSON.writeValueAsString(new EventEnvelope("payment", good.payload(), "AAAA"));
        assertTrue(accept(bad).isEmpty());
        assertTrue(accept(JSON.writeValueAsString(good)).isPresent());
    }

    @Test
    void refusalsCarryTheirTypedReason() throws Exception {
        assertEquals(EventVerifier.Refusal.MALFORMED_ENVELOPE, auth.accept("not json").refusal());
        assertEquals(EventVerifier.Refusal.SIGNER_NOT_ALLOWED,
                auth.accept(envelope("search", search, eventJson(NOW, "a"))).refusal());
        assertEquals(EventVerifier.Refusal.BAD_SIGNATURE,
                auth.accept(envelope("payment", search, eventJson(NOW, "a"))).refusal());
        assertEquals(EventVerifier.Refusal.OUTSIDE_WINDOW,
                auth.accept(envelope("payment", payment, eventJson(NOW - 30_001, "a"))).refusal());
        assertEquals(EventVerifier.Refusal.REPEATED_EVENT_ID, repeat().refusal());
    }

    private EventVerifier.Outcome repeat() throws Exception {
        String body = envelope("payment", payment, eventJson(NOW, "r"));
        auth.accept(body);
        return auth.accept(body);
    }

    @Test
    void onlyAnAllowedSignersNameTravelsWithTheRefusal() throws Exception {
        EventVerifier keyless = new EventVerifier(
                Keyring.of(Map.of("search", search.getPublic())), Set.of("payment"), clock::get);
        EventVerifier.Outcome unknown = keyless.accept(envelope("payment", payment, eventJson(NOW, "a")));
        assertEquals(EventVerifier.Refusal.UNKNOWN_SIGNER, unknown.refusal());
        assertEquals("payment", unknown.signer());
        assertEquals(null, auth.accept("{\"signer\":\"x\\ny\",\"payload\":\"e30\",\"sig\":\"AAAA\"}").signer());
    }
}
