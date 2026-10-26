// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.EventEnvelope;

class ResponderEventPublisherTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AttestationEvent EVENT =
            new AttestationEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", false);

    private final KeyPair key = Crypto.generateEd25519KeyPair();
    private final ResponderEventPublisher publisher =
            new ResponderEventPublisher("http://127.0.0.1:1", "payment", key.getPrivate(), () -> 1234L);

    @Test
    void publishIsBestEffortWhenResponderIsUnreachable() {
        // Port 1 refuses connections; publishing must never break verification.
        assertDoesNotThrow(() -> publisher.publish(EVENT));
    }

    @Test
    void envelopeVerifiesWithThePublicKeyAndCarriesTheEvent() throws Exception {
        EventEnvelope env = publisher.envelope(EVENT);
        assertEquals("payment", env.signer());
        assertTrue(env.verifiesWith(key.getPublic()));

        JsonNode event = JSON.readTree(new String(env.payloadBytes(), StandardCharsets.UTF_8));
        assertEquals("PATH_NOT_ALLOWED", event.get("reason").asText());
        assertEquals("search", event.get("suspectSvc").asText());
        assertEquals("s1", event.get("suspectInst").asText());
        assertEquals("rid", event.get("rid").asText());
        assertEquals(false, event.get("audit").asBoolean());
        assertEquals(1234L, event.get("ts").asLong());
        assertTrue(event.get("eventId").asText().length() >= 32);
    }

    @Test
    void signedBytesStartWithTheDomainPrefix() {
        EventEnvelope env = publisher.envelope(EVENT);
        byte[] expected = ("paztport-event\n" + env.payload()).getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(key.getPublic(), expected,
                org.paztport.core.Base64Url.decode(env.sig())));
    }

    @Test
    void everyEventGetsItsOwnId() {
        assertNotEquals(publisher.envelope(EVENT).payload(), publisher.envelope(EVENT).payload());
    }
}
