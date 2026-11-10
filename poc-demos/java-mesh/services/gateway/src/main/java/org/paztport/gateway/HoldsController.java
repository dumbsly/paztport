// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Holds items: gateway, orders, and from orders one call to payment for each item. The answer from orders is relayed
 * as it is, so the status payment gave each item shows in the reply.
 */
@RestController
public class HoldsController {

    /** The items to hold. */
    public record Holds(List<String> items) {
    }

    private final RestClient http;
    private final String ordersUrl;

    public HoldsController(RestClient http, @Value("${downstream.orders-url}") String ordersUrl) {
        this.http = http;
        this.ordersUrl = ordersUrl;
    }

    @PostMapping("/holds")
    public ResponseEntity<?> holds(@RequestBody Holds holds) {
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(ordersUrl + "/holds")
                .contentType(MediaType.APPLICATION_JSON)
                .body(holds)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }
}
