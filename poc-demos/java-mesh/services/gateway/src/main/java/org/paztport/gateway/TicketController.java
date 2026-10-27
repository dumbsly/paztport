// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * A customer submits a support ticket: plain text, which goes to tickets with the customer the bearer token names
 * as its author. The author comes from the token, never from the text. The answer from downstream is relayed as it
 * is, refusals included.
 */
@RestController
public class TicketController {

    private final RestClient http;
    private final DemoTokens tokens;
    private final String ticketsUrl;

    public TicketController(RestClient http, DemoTokens tokens, @Value("${downstream.tickets-url}") String ticketsUrl) {
        this.http = http;
        this.tokens = tokens;
        this.ticketsUrl = ticketsUrl;
    }

    @PostMapping("/tickets")
    public ResponseEntity<?> ticket(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestBody(required = false) String text) {
        String customer = tokens.customerFor(authorization);
        if (customer == null) {
            return ResponseEntity.status(401).body(Map.of("reason", "UNAUTHORIZED"));
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("author", customer);
        body.put("text", text == null ? "" : text);
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(ticketsUrl + "/tickets")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }
}
