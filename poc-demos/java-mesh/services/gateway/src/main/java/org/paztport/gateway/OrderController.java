// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Reads one order: the route through orders' {@code getOrder}, an operation that never calls payment. The answer
 * from orders is relayed as it is, a {@code 404} included.
 */
@RestController
public class OrderController {

    private final RestClient http;
    private final String ordersUrl;

    public OrderController(RestClient http, @Value("${downstream.orders-url}") String ordersUrl) {
        this.http = http;
        this.ordersUrl = ordersUrl;
    }

    @GetMapping("/orders/{id}")
    public ResponseEntity<byte[]> order(@PathVariable String id) {
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.get()
                .uri(ordersUrl + "/orders/{id}", id)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }
}
