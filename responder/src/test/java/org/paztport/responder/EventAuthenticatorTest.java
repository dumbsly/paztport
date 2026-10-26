// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.EventEnvelope;
import org.paztport.core.Keyring;

class EventAuthenticatorTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long NOW = 1_000_000L;

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair search = Crypto.generateEd25519KeyPair();
    private final AtomicLong clock = new AtomicLong(NOW);
    private final EventAuthenticator auth = new EventAuthenticator(
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
        return auth.accept(body);
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
}
