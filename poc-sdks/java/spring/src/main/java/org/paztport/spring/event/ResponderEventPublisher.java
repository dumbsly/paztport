// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.event;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.paztport.core.event.EventEnvelope;
import org.paztport.spring.internal.WholeExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Publishes events to the responder as well as the log. Each event is wrapped in
 * an {@link EventEnvelope} signed with this service's own key, because the
 * responder acts on events and must not take them from anyone on the mesh. The
 * POST is best-effort: a responder outage must never fail verification, so
 * failures are swallowed (and logged) rather than propagated.
 *
 * <p>Nor may it hold verification up for long. The event is sent on the request
 * thread, before a refusal is answered, so a responder that is slow or silent
 * would otherwise hold every refusal for as long as it liked. So the whole POST,
 * connecting, sending and reading the answer to its end, is bounded by the event
 * timeout ({@code paztport.event-timeout-ms}, 2 s unless set) on every JDK; past
 * it the POST is cancelled, logged as any other failure, and the refusal goes
 * ahead. A refusal therefore waits at most that long for its event. That caps the
 * wait per refusal, no more: forged requests sent fast enough can still keep
 * request threads busy, each for up to that long, while the responder is slow.
 *
 * <p>The JDK client is given, not built here, so that it can carry this service's
 * TLS certificate, and as a supplier, so that a TLS client still reads its key
 * material on the first event rather than at startup. Being the bare JDK client,
 * it never stamps: an event reports on a request's path, it is not a step on it.
 */
public final class ResponderEventPublisher implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(ResponderEventPublisher.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The event as the responder reads it: the verdict plus a timestamp and a unique id. */
    private record Wire(String reason, String suspectSvc, String suspectInst, String rid, boolean audit,
            long ts, String eventId) {
    }

    private final EventPublisher logging = new LoggingEventPublisher();
    private final Supplier<HttpClient> http;
    private final Duration timeout;
    private final String responderUrl;
    private final String signer;
    private final PrivateKey key;
    private final LongSupplier clock;

    /**
     * @param http the JDK client each event is sent on, asked for at each event
     * @param timeout how long one event may take, from connecting to the end of the answer; positive
     * @param responderUrl the responder's base URL; events go to {@code /events} under it
     * @param signer this service's name, which the responder looks its key up by
     * @param key this service's event key
     * @param clock the time each event carries, in milliseconds since the epoch
     * @throws IllegalArgumentException when {@code timeout} is not positive
     */
    public ResponderEventPublisher(Supplier<HttpClient> http, Duration timeout, String responderUrl, String signer,
            PrivateKey key, LongSupplier clock) {
        this.http = Objects.requireNonNull(http, "http");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("the event timeout must be positive: " + timeout);
        }
        this.responderUrl = responderUrl;
        this.signer = signer;
        this.key = key;
        this.clock = clock;
    }

    @Override
    public void publish(AttestationEvent event) {
        logging.publish(event);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(responderUrl + "/events"))
                    .header("Content-Type", "application/json")
                    .timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(envelope(event))))
                    .build();
            int status = WholeExchange.send(http.get(), request, HttpResponse.BodyHandlers.discarding())
                    .statusCode();
            if (status >= 400) {
                log.warn("the responder at {} refused the event: {}", responderUrl, status);
            }
        } catch (IOException | RuntimeException e) {
            log.warn("could not reach responder at {}: {}", responderUrl, e.getMessage());
        }
    }

    /** How long one event may take. */
    public Duration timeout() {
        return timeout;
    }

    EventEnvelope envelope(AttestationEvent event) {
        Wire wire = new Wire(event.reason(), event.suspectSvc(), event.suspectInst(), event.rid(), event.audit(),
                clock.getAsLong(), UUID.randomUUID().toString());
        try {
            return EventEnvelope.sign(signer, JSON.writeValueAsBytes(wire), key);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode event", e);
        }
    }
}
