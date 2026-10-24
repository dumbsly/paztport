// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Publishes events to the responder as well as the log. The POST is best-effort:
 * a responder outage must never block or fail verification, so failures are
 * swallowed (and logged) rather than propagated.
 */
public final class ResponderEventPublisher implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(ResponderEventPublisher.class);

    private final EventPublisher logging = new LoggingEventPublisher();
    private final RestClient http = RestClient.create();
    private final String responderUrl;

    public ResponderEventPublisher(String responderUrl) {
        this.responderUrl = responderUrl;
    }

    @Override
    public void publish(AttestationEvent event) {
        logging.publish(event);
        try {
            http.post()
                    .uri(responderUrl + "/events")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(event)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException e) {
            log.warn("could not reach responder at {}: {}", responderUrl, e.getMessage());
        }
    }
}
