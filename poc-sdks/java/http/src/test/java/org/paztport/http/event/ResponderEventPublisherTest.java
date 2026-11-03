// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.event;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.event.EventEnvelope;
import org.paztport.core.event.EventVerifier;
import org.paztport.core.event.ResponderEvent;
import org.paztport.core.policy.Keyring;
import org.paztport.http.SilentPeer;
import org.slf4j.LoggerFactory;

class ResponderEventPublisherTest {

    private static final AttestationEvent EVENT =
            new AttestationEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", false);

    /** One JDK client for every test; its connect wait is bounded so that a call nobody answers fails the test. */
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();

    private final KeyPair key = Crypto.generateEd25519KeyPair();
    private final ResponderEventPublisher publisher = publisherTo("http://127.0.0.1:1", Duration.ofSeconds(2));

    private ResponderEventPublisher publisherTo(String url, Duration timeout) {
        return new ResponderEventPublisher(HTTP, timeout, url, "payment", key.getPrivate(), () -> 1234L);
    }

    /** The event a responder that takes payment's events reads from {@code body}, or null if it refuses it. */
    private ResponderEvent read(String body) {
        return new EventVerifier(List.of(Keyring.of(Map.of("payment", key.getPublic()))), Set.of("payment"),
                () -> 1234L).accept(body).event();
    }

    @AfterAll
    static void closeClient() {
        HTTP.close();
    }

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

        ResponderEvent event = read(env.toJson());
        assertEquals(EVENT.sentAt(1234L, event.eventId()), event);
        assertTrue(event.eventId().length() >= 32);
    }

    @Test
    void signedBytesStartWithTheDomainPrefix() {
        EventEnvelope env = publisher.envelope(EVENT);
        byte[] expected = ("paztport-event\n" + env.payload()).getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(key.getPublic(), expected,
                org.paztport.core.encoding.Base64Url.decode(env.sig())));
    }

    @Test
    void everyEventGetsItsOwnId() {
        assertNotEquals(publisher.envelope(EVENT).payload(), publisher.envelope(EVENT).payload());
    }

    /** What a test responder was sent: the path, the content type and the body. */
    private record Received(String path, String contentType, byte[] body) {
    }

    @Test
    void postsTheSignedEnvelopeAsJsonToEvents() throws Exception {
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpServer responder = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        responder.createContext("/", exchange -> {
            received.add(new Received(exchange.getRequestURI().getPath(),
                    exchange.getRequestHeaders().getFirst("Content-Type"), exchange.getRequestBody().readAllBytes()));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        responder.start();
        try {
            publisherTo("http://127.0.0.1:" + responder.getAddress().getPort(), Duration.ofSeconds(2)).publish(EVENT);

            Received r = received.poll(5, TimeUnit.SECONDS);
            assertTrue(r != null, "the responder got the event");
            assertEquals("/events", r.path());
            assertEquals("application/json", r.contentType());
            ResponderEvent sent = read(new String(r.body(), StandardCharsets.UTF_8));
            assertTrue(sent != null, "the responder accepts what was posted");
            assertEquals("PATH_NOT_ALLOWED", sent.reason());
        } finally {
            responder.stop(0);
        }
    }

    /**
     * A responder that takes the event and never finishes answering, before its headers or part way through the
     * body: publish gives up at the event timeout, on any JDK, logs it and returns, as for any other failure. On
     * JDK 27 the JDK's own request timeout also ends a stalled body, so there the body case passes even without the
     * publisher's whole-exchange bound; on JDK 25, which applies a request's timeout only to the headers, it shows
     * that bound.
     */
    @Test
    void aSilentResponderIsGivenUpAtTheEventTimeout() throws Exception {
        Logger log = (Logger) LoggerFactory.getLogger(ResponderEventPublisher.class);
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        warnings.start();
        log.addAppender(warnings);
        log.setLevel(Level.WARN);
        try {
            for (SilentPeer.Stall stall : SilentPeer.Stall.values()) {
                try (SilentPeer responder = new SilentPeer(stall)) {
                    ResponderEventPublisher silent = publisherTo(responder.url(), Duration.ofMillis(300));

                    long start = System.nanoTime();
                    assertDoesNotThrow(() -> silent.publish(EVENT));
                    Duration took = Duration.ofNanos(System.nanoTime() - start);

                    assertEquals(1, responder.connections(), stall.name());
                    assertTrue(took.compareTo(Duration.ofMillis(250)) >= 0
                            && took.compareTo(Duration.ofSeconds(3)) < 0, stall + " took " + took);
                }
            }
            assertEquals(2, warnings.list.stream()
                    .filter(e -> e.getFormattedMessage().startsWith("could not reach responder")).count());
        } finally {
            log.detachAppender(warnings);
            log.setLevel(null);
        }
    }

    @Test
    void theTimeoutMustBePositive() {
        for (Duration bad : new Duration[] {Duration.ZERO, Duration.ofMillis(-1)}) {
            assertThrows(IllegalArgumentException.class, () -> publisherTo("http://127.0.0.1:1", bad));
        }
        assertThrows(NullPointerException.class, () -> publisherTo("http://127.0.0.1:1", null));
    }
}
