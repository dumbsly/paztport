// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.intent.IntentFacts;
import org.paztport.http.OriginIntent;
import org.paztport.http.RequestContext;
import org.paztport.spring.intent.RequiresIntent;
import org.springframework.beans.factory.ObjectProvider;
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

    /** The items a customer asks to hold. */
    public record Holds(List<String> items) {
    }

    private final RestClient http;
    private final OrderBook book;
    private final String paymentUrl;
    private final ObjectProvider<StolenChainStore> stolenChains;
    private final OriginIntent intent;
    private final ObjectProvider<ChargeTamper> tampers;

    /**
     * {@code stolenChains} has a store only with the attack demo on; each order read or placed gives it its chain and
     * the blocks that came with it. {@code tampers} has a {@link ChargeTamper} only with the attack demo on.
     */
    public OrdersController(RestClient http, OrderBook book, @Value("${downstream.payment-url}") String paymentUrl,
            ObjectProvider<StolenChainStore> stolenChains, OriginIntent intent, ObjectProvider<ChargeTamper> tampers) {
        this.http = http;
        this.book = book;
        this.paymentUrl = paymentUrl;
        this.stolenChains = stolenChains;
        this.intent = intent;
        this.tampers = tampers;
    }

    /** One order, labelled with its customer; {@code 404} when there is none. */
    @GetMapping("/orders/{id}")
    public ResponseEntity<?> byId(@PathVariable String id) {
        stolenChains.ifAvailable(store -> store.recordGetOrder(RequestContext.inboundChain(),
                RequestContext.inboundBlocks()));
        OrderBook.Order order = book.byId(id);
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        RequestContext.label(InfluenceClass.PRIVATE, order.customer());
        return ResponseEntity.ok(order);
    }

    /** The orders placed with an address, labelled with their customer when there is one. */
    @GetMapping("/orders")
    public Map<String, List<OrderBook.Order>> byEmail(@RequestParam String email) {
        List<OrderBook.Order> found = book.byEmail(email);
        found.stream().map(OrderBook.Order::customer).distinct()
                .forEach(customer -> RequestContext.label(InfluenceClass.PRIVATE, customer));
        return Map.of("orders", found);
    }

    @PostMapping("/orders")
    public Map<String, Object> order(@RequestBody(required = false) String ignored) {
        stolenChains.ifAvailable(store -> store.recordCreateOrder(RequestContext.inboundChain(),
                RequestContext.inboundBlocks()));
        String payment = http.post()
                .uri(paymentUrl + "/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"amount\":100}")
                .retrieve()
                .body(String.class);
        return Map.of("order", "OK", "payment", payment);
    }

    /**
     * Charges an order through payment, which takes it to the PSP. Only the order's own customer may pay for it,
     * refused {@code 403 NOT_YOUR_ORDER} otherwise: the PSP takes whoever pays for an order as the one a refund of it
     * may go to. Payment's answer is relayed as it is, refusals included.
     *
     * <p>The gateway states the customer, the order and the amount the customer was shown as facts ({@code intent}).
     * A purchase whose facts name another customer or order, or an amount that is not the order book's, is refused
     * {@code 403 INTENT_DENIED}: the customer was shown another price, or a hop changed the request. The charge is
     * built from the facts, the values compared, and the card from the request, which is not a fact.
     */
    @PostMapping("/purchase")
    @RequiresIntent({"amount", "customer", "order"})
    public ResponseEntity<?> purchase(@RequestBody Purchase purchase) {
        OrderBook.Order order = book.byId(purchase.order());
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        if (!order.customer().equals(purchase.customer())) {
            return ResponseEntity.status(403).body(Map.of("reason", "NOT_YOUR_ORDER"));
        }
        IntentFacts facts = intent.facts();
        if (!purchase.customer().equals(facts.string("customer")) || !purchase.order().equals(facts.string("order"))
                || !Long.valueOf(order.amount()).equals(facts.integer("amount"))) {
            return ResponseEntity.status(403).body(Map.of("reason", intent.deny().name()));
        }
        Map<String, Object> charge = new LinkedHashMap<>();
        charge.put("customer", facts.string("customer"));
        charge.put("order", facts.string("order"));
        charge.put("card", purchase.card());
        charge.put("amount", facts.integer("amount"));
        // Only with the attack demo on: code in a compromised orders changing the charge after the comparison.
        tampers.ifAvailable(tamper -> tamper.apply(charge));
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(paymentUrl + "/charge")
                .contentType(MediaType.APPLICATION_JSON)
                .body(charge)
                .exchange((request, response) -> ResponseEntity.status(response.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.getBody().readAllBytes()));
    }

    /**
     * Asks payment to hold each item, in order, and answers each item's status. The hold is keyed by item, so
     * payment takes one call per item in a request tree: an item named twice is held the first time and refused
     * {@code 403 REPLAY} the second. A refusal is reported against its item, with the reason payment gave, not thrown.
     */
    @PostMapping("/holds")
    public Map<String, Object> holdItems(@RequestBody Holds holds) {
        stolenChains.ifAvailable(store -> store.recordHoldItems(RequestContext.inboundChain(),
                RequestContext.inboundBlocks()));
        List<Map<String, Object>> results = new ArrayList<>();
        for (String item : holds.items()) {
            // exchange applies no status handlers, so a refusal downstream is reported rather than thrown.
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("item", item);
            http.post()
                    .uri(paymentUrl + "/holds/" + item)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        result.put("status", status);
                        if (response.getStatusCode().isError()) {
                            Map<?, ?> refusal = response.bodyTo(Map.class);
                            result.put("reason", refusal == null ? null : refusal.get("reason"));
                        }
                        return null;
                    });
            results.add(result);
        }
        return Map.of("holds", results);
    }
}
