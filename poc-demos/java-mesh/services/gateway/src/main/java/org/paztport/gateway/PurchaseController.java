// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.LinkedHashMap;
import java.util.Map;
import org.paztport.core.intent.IntentFacts;
import org.paztport.http.RequestContext;
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
 *
 * <p>The gateway is the origin, and it states the purchase as facts ({@code intent}): the customer, the order and the
 * amount the customer was shown. Payment, two hops on, compares the charge it is asked for with them, so a hop
 * between that changes the amount, the order or the customer is refused there. A purchase with no card is refused
 * {@code 400 NO_CARD}, one with no amount {@code 400 NO_AMOUNT}, and one whose amount is outside 0 to 2^53 &minus; 1,
 * which no fact can hold, {@code 400 BAD_AMOUNT}; none of them reaches orders.
 */
@RestController
public class PurchaseController {

    /** The largest protocol integer, 2^53 &minus; 1: a fact's integer value is from 0 to this. */
    private static final long MAX_AMOUNT = 9_007_199_254_740_991L;

    /** What the customer sends: the order, the card to pay with, and the amount the customer was shown for it. */
    public record Purchase(String order, String card, Long amount) {
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
        if (purchase.order() == null) {
            // As orders answers an order it does not hold; with no order there is no fact to state.
            return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
        }
        if (purchase.card() == null || purchase.card().isBlank()) {
            return ResponseEntity.status(400).body(Map.of("reason", "NO_CARD"));
        }
        if (purchase.amount() == null) {
            return ResponseEntity.status(400).body(Map.of("reason", "NO_AMOUNT"));
        }
        if (purchase.amount() < 0 || purchase.amount() > MAX_AMOUNT) {
            // Not a value a fact can hold, so no price the customer could have been shown.
            return ResponseEntity.status(400).body(Map.of("reason", "BAD_AMOUNT"));
        }
        // Every call this request makes from here states these facts in the gateway's block.
        RequestContext.sealIntent(IntentFacts.builder()
                .put("customer", customer)
                .put("order", purchase.order())
                .put("amount", purchase.amount())
                .build());
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
