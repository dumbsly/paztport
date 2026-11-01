// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.event.EventEnvelope;
import org.paztport.http.internal.LogSafe;

class EventsTest {

    @Test
    void loggingPublisherFormatsAStructuredLine() {
        AttestationEvent event = new AttestationEvent("PATH_NOT_ALLOWED", "search", "search-1", "rid-9", true);
        String line = LoggingEventPublisher.format(event);

        assertTrue(line.contains("reason=PATH_NOT_ALLOWED"));
        assertTrue(line.contains("suspectSvc=search"));
        assertTrue(line.contains("suspectInst=search-1"));
        assertTrue(line.contains("rid=rid-9"));
        assertTrue(line.contains("audit=true"));
    }

    @Test
    void loggingPublisherKeepsAForgedNewlineOnOneLine() {
        AttestationEvent event = new AttestationEvent(
                "PATH_NOT_ALLOWED", "search", "s1\nPAZTPORT_EVENT reason=OK", "rid\r9", false);
        String line = LoggingEventPublisher.format(event);

        assertFalse(line.contains("\n"), line);
        assertFalse(line.contains("\r"), line);
        assertTrue(line.contains("suspectInst=s1\\u000aPAZTPORT_EVENT"), line);
    }

    @Test
    void logSafeCapsLongValues() {
        assertEquals("x".repeat(LogSafe.MAX_CHARS) + "...", LogSafe.of("x".repeat(10_000)));
        assertEquals("null", LogSafe.of(null));
    }

    /** The publisher sends the envelope's JCS text over the event's JCS bytes, the only form a responder reads. */
    @Test
    void aPublishedEventIsItsJcsText() {
        KeyPair key = Crypto.generateEd25519KeyPair();
        EventEnvelope env;
        try (HttpClient http = HttpClient.newHttpClient()) {
            env = new ResponderEventPublisher(http, Duration.ofSeconds(1), "http://127.0.0.1:1", "payment",
                    key.getPrivate(), () -> 1234L)
                    .envelope(new AttestationEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", false));
        }
        String event = new String(env.payloadBytes(), StandardCharsets.UTF_8);
        String id = event.substring("{\"audit\":false,\"eventId\":\"".length(), event.indexOf("\",\"reason\""));
        assertEquals("{\"audit\":false,\"eventId\":\"" + id + "\",\"reason\":\"PATH_NOT_ALLOWED\",\"rid\":\"rid\","
                + "\"suspectInst\":\"s1\",\"suspectSvc\":\"search\",\"ts\":1234}", event);
        assertEquals("{\"payload\":\"" + env.payload() + "\",\"sig\":\"" + env.sig() + "\",\"signer\":\"payment\"}",
                env.toJson());
    }
}
