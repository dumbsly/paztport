// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.InfluenceClass;
import org.paztport.spring.PaztportContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Appends its stamp (via the interceptor) and calls payment; and answers reads of the order book.
 *
 * <p>An order is private to the customer who placed it, so every read labels its answer {@code private} with that
 * customer as owner. The label goes back attested, so whoever read it carries it on every call after: a later write
 * somewhere public is then judged knowing whose data shaped it.
 */
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

    /** One order, labelled with its customer; {@code 404} when there is none. */
    @GetMapping("/orders/{id}")
    public ResponseEntity<?> byId(@PathVariable String id) {
        OrderBook.Order order = book.byId(id);
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        PaztportContext.label(InfluenceClass.PRIVATE, order.customer());
        return ResponseEntity.ok(order);
    }

    /** The orders placed with an address, labelled with their customer when there is one. */
    @GetMapping("/orders")
    public Map<String, List<OrderBook.Order>> byEmail(@RequestParam String email) {
        List<OrderBook.Order> found = book.byEmail(email);
        found.stream().map(OrderBook.Order::customer).distinct()
                .forEach(customer -> PaztportContext.label(InfluenceClass.PRIVATE, customer));
        return Map.of("orders", found);
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
     * request. Only the order's own customer may pay for it, refused {@code 403 NOT_YOUR_ORDER} otherwise: the PSP
     * takes whoever pays for an order as the one a refund of it may go to. Payment's answer is relayed as it is,
     * refusals included.
     */
    @PostMapping("/purchase")
    public ResponseEntity<?> purchase(@RequestBody Purchase purchase) {
        OrderBook.Order order = book.byId(purchase.order());
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        if (!order.customer().equals(purchase.customer())) {
            return ResponseEntity.status(403).body(Map.of("reason", "NOT_YOUR_ORDER"));
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
