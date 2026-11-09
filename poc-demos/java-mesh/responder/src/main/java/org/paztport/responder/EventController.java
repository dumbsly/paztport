// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.Map;
import org.paztport.core.event.EventVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives rejection events from verifying services. The body is taken as raw
 * text so the signature is checked over exactly what was sent; anything the
 * {@link EventVerifier} refuses gets a 403 and no decision is taken. The refusal
 * reason is logged here, since core does no logging; the signer is the only
 * sender-supplied text and appears only for refusals that follow the allow-list,
 * but it still goes through {@link LogSafe}.
 */
@RestController
public class EventController {

    private static final Logger LOG = LoggerFactory.getLogger(EventController.class);

    private final ResponderService service;
    private final EventVerifier verifier;

    public EventController(ResponderService service, EventVerifier verifier) {
        this.service = service;
        this.verifier = verifier;
    }

    @PostMapping("/events")
    public ResponseEntity<Map<String, String>> events(@RequestBody(required = false) String body) {
        EventVerifier.Outcome outcome = verifier.accept(body);
        if (!outcome.accepted()) {
            LOG.warn("refused event: {}", why(outcome));
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "event refused"));
        }
        return ResponseEntity.ok(Map.of("decision", service.handle(outcome.event()).name()));
    }

    private static String why(EventVerifier.Outcome outcome) {
        return switch (outcome.refusal()) {
            case MALFORMED_ENVELOPE -> "malformed envelope";
            case SIGNER_NOT_ALLOWED -> "signer not allowed";
            case UNKNOWN_SIGNER -> "unknown signer: " + LogSafe.of(outcome.signer());
            case BAD_SIGNATURE -> "bad signature from " + LogSafe.of(outcome.signer());
            case MALFORMED_EVENT -> "malformed event";
            case NO_EVENT_ID -> "event has no id";
            case OUTSIDE_WINDOW -> "event outside the freshness window";
            case REPEATED_EVENT_ID -> "repeated event id";
        };
    }
}
