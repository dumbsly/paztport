// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/** Appends its stamp (via the interceptor) and calls payment. */
@RestController
public class OrdersController {

    /** A purchase as the gateway sends it, with the customer its token named. */
    public record Purchase(String customer, String order, String card) {
    }

    private final RestClient http;
    private final OrderBook book;
    private final String paymentUrl;

    public OrdersController(RestClient http, OrderBook book, @Value("${downstream.payment-url}") String paymentUrl) {
        this.http = http;
        this.book = book;
        this.paymentUrl = paymentUrl;
    }

    @PostMapping("/orders")
    public Map<String, Object> order(@RequestBody(required = false) String ignored) {
        String payment = http.post()
                .uri(paymentUrl + "/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"amount\":100}")
                .retrieve()
                .body(String.class);
        return Map.of("order", "OK", "payment", payment);
    }

    /**
     * Charges an order through payment, which takes it to the PSP. The amount comes from the order book, not the
     * request. Payment's answer is relayed as it is, refusals included.
     */
    @PostMapping("/purchase")
    public ResponseEntity<?> purchase(@RequestBody Purchase purchase) {
        OrderBook.Order order = book.byId(purchase.order());
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        Map<String, Object> charge = new LinkedHashMap<>();
        charge.put("customer", purchase.customer());
        charge.put("order", order.id());
        charge.put("card", purchase.card());
        charge.put("amount", order.amount());
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(paymentUrl + "/charge")
                .contentType(MediaType.APPLICATION_JSON)
                .body(charge)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }
}
