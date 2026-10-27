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
 * A customer pays for an order: gateway, orders, payment, and from payment across the boundary to the PSP. The
 * customer comes from the bearer token, never from the body, since the PSP registers each card to the customer of
 * its first attested charge. The answer from downstream is relayed as it is, refusals included.
 */
@RestController
public class PurchaseController {

    /** What the customer sends: the order and the card to pay with. */
    public record Purchase(String order, String card) {
    }

    private final RestClient http;
    private final DemoTokens tokens;
    private final String ordersUrl;

    public PurchaseController(RestClient http, DemoTokens tokens, @Value("${downstream.orders-url}") String ordersUrl) {
        this.http = http;
        this.tokens = tokens;
        this.ordersUrl = ordersUrl;
    }

    @PostMapping("/purchase")
    public ResponseEntity<?> purchase(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestBody Purchase purchase) {
        String customer = tokens.customerFor(authorization);
        if (customer == null) {
            return ResponseEntity.status(401).body(Map.of("reason", "UNAUTHORIZED"));
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("customer", customer);
        body.put("order", purchase.order());
        body.put("card", purchase.card());
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(ordersUrl + "/purchase")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }
}
