// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Receives rejection events from verifying services. */
@RestController
public class EventController {

    private final ResponderService service;

    public EventController(ResponderService service) {
        this.service = service;
    }

    @PostMapping("/events")
    public Map<String, String> events(@RequestBody ResponderEvent event) {
        return Map.of("decision", service.handle(event).name());
    }
}
