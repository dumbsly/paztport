// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives rejection events from verifying services. The body is taken as raw
 * text so the signature is checked over exactly what was sent; anything the
 * {@link EventAuthenticator} refuses gets a 403 and no decision is taken.
 */
@RestController
public class EventController {

    private final ResponderService service;
    private final EventAuthenticator authenticator;

    public EventController(ResponderService service, EventAuthenticator authenticator) {
        this.service = service;
        this.authenticator = authenticator;
    }

    @PostMapping("/events")
    public ResponseEntity<Map<String, String>> events(@RequestBody(required = false) String body) {
        Optional<ResponderEvent> event = authenticator.accept(body);
        if (event.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "event refused"));
        }
        return ResponseEntity.ok(Map.of("decision", service.handle(event.get()).name()));
    }
}
