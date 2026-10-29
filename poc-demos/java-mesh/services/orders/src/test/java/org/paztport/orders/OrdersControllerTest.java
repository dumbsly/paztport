// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.spring.PaztportContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class OrdersControllerTest {

    private MockRestServiceServer payment;
    private OrdersController controller;

    @BeforeEach
    void start() {
        RestClient.Builder http = RestClient.builder();
        payment = MockRestServiceServer.bindTo(http).build();
        controller = new OrdersController(http.build(), new OrderBook(), "https://payment:8080");
    }

    // The PSP registers a card to whoever pays for an order, so only the order's own customer may pay for it.
    @Test
    void purchaseOfAnotherCustomersOrderIsRefused() {
        ResponseEntity<?> response = controller.purchase(
                new OrdersController.Purchase("mallory", "123", "4000 0000 0000 0002"));

        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NOT_YOUR_ORDER"), response.getBody());
        payment.verify();
    }

    @Test
    void purchaseOfOwnOrderGoesToPayment() {
        payment.expect(requestTo("https://payment:8080/charge")).andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("{\"status\":\"CHARGED\"}", MediaType.APPLICATION_JSON));

        ResponseEntity<?> response = controller.purchase(
                new OrdersController.Purchase("alice", "123", "4242 4242 4242 4242"));

        assertEquals(200, response.getStatusCode().value());
        payment.verify();
    }

    // The label is what the storyline turns on: an order read carries its customer as owner on every later call.
    @Test
    void anOrderIsLabelledPrivateToItsCustomer() {
        List<ContentLabel> labels;
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            assertEquals(200, controller.byId("123").getStatusCode().value());
            labels = PaztportContext.labels();
        }

        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
    }
}
