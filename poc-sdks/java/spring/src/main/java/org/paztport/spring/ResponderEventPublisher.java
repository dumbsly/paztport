// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.PrivateKey;
import java.util.UUID;
import java.util.function.LongSupplier;
import org.paztport.core.EventEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Publishes events to the responder as well as the log. Each event is wrapped in
 * an {@link EventEnvelope} signed with this service's own key, because the
 * responder acts on events and must not take them from anyone on the mesh. The
 * POST is best-effort: a responder outage must never block or fail verification,
 * so failures are swallowed (and logged) rather than propagated.
 */
public final class ResponderEventPublisher implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(ResponderEventPublisher.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The event as the responder reads it: the verdict plus a timestamp and a unique id. */
    private record Wire(String reason, String suspectSvc, String suspectInst, String rid, boolean audit,
            long ts, String eventId) {
    }

    private final EventPublisher logging = new LoggingEventPublisher();
    private final RestClient http = RestClient.create();
    private final String responderUrl;
    private final String signer;
    private final PrivateKey key;
    private final LongSupplier clock;

    public ResponderEventPublisher(String responderUrl, String signer, PrivateKey key, LongSupplier clock) {
        this.responderUrl = responderUrl;
        this.signer = signer;
        this.key = key;
        this.clock = clock;
    }

    @Override
    public void publish(AttestationEvent event) {
        logging.publish(event);
        try {
            http.post()
                    .uri(responderUrl + "/events")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(envelope(event))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException e) {
            log.warn("could not reach responder at {}: {}", responderUrl, e.getMessage());
        }
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
