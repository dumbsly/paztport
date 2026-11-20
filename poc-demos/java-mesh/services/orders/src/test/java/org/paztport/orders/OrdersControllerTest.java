// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.http.OriginIntent;
import org.paztport.http.RequestContext;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
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
        StaticListableBeanFactory none = new StaticListableBeanFactory();
        controller = new OrdersController(http.build(), new OrderBook(), "https://payment:8080",
                none.getBeanProvider(StolenChainStore.class), new OriginIntent("orders"),
                none.getBeanProvider(ChargeTamper.class));
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

    // The gateway seals the amount the customer was shown; the order book says what the order costs. A difference
    // is the customer's or a hop's, and orders charges neither.
    @Test
    void anAmountThatIsNotTheBooksIsDenied() {
        ResponseEntity<?> response = OriginFacts.servedWith(OriginFacts.alicePays(1), () -> controller.purchase(
                new OrdersController.Purchase("alice", "123", "4242 4242 4242 4242")));

        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INTENT_DENIED"), response.getBody());
        payment.verify();
    }

    @Test
    void anotherCustomersFactsAreDenied() {
        IntentFacts mallorys = IntentFacts.builder().put("customer", "mallory").put("order", "123").put("amount", 100)
                .build();

        ResponseEntity<?> response = OriginFacts.servedWith(mallorys, () -> controller.purchase(
                new OrdersController.Purchase("alice", "123", "4242 4242 4242 4242")));

        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INTENT_DENIED"), response.getBody());
        payment.verify();
    }

    // Orders acts on the values it compared: the customer, order and amount of the charge are the facts', and only
    // the card, which is not a fact, is the request's.
    @Test
    void theChargeIsBuiltFromTheFacts() {
        payment.expect(requestTo("https://payment:8080/charge")).andExpect(method(HttpMethod.POST))
                .andExpect(content().string(
                        "{\"customer\":\"alice\",\"order\":\"123\",\"card\":\"4242 4242 4242 4242\",\"amount\":100}"))
                .andRespond(withSuccess("{\"status\":\"CHARGED\"}", MediaType.APPLICATION_JSON));

        ResponseEntity<?> response = OriginFacts.servedWith(OriginFacts.alicePays(100), () -> controller.purchase(
                new OrdersController.Purchase("alice", "123", "4242 4242 4242 4242")));

        assertEquals(200, response.getStatusCode().value());
        payment.verify();
    }

    // The label is what the storyline turns on: an order read carries its customer as owner on every later call.
    @Test
    void anOrderIsLabelledPrivateToItsCustomer() {
        List<ContentLabel> labels;
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertEquals(200, controller.byId("123").getStatusCode().value());
            labels = RequestContext.labels();
        }

        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
    }

    // With the attack demo enabled, the chain a getOrder was served on is kept, with its blocks, for the attack
    // endpoints to steer.
    @Test
    void anOrderReadIsRecordedWhenTheAttackDemoIsEnabled() throws Exception {
        StolenChainStore store = new StolenChainStore();
        StaticListableBeanFactory beans = new StaticListableBeanFactory(Map.of("store", store));
        OrdersController recording = new OrdersController(RestClient.builder().build(), new OrderBook(),
                "https://payment:8080", beans.getBeanProvider(StolenChainStore.class), new OriginIntent("orders"),
                beans.getBeanProvider(ChargeTamper.class));
        List<Stamp> chain = List.of(Stamp.sign("gateway", "gw-1", "rid-1", 1, "", "orders#getOrder", "bind", "", "",
                KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate()));

        List<Block> blocks = List.of(Block.EMPTY);

        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(chain, blocks);
            recording.byId("123");
        }

        assertSame(chain, store.getOrder().chain());
        assertEquals(blocks, store.getOrder().blocks());
        assertNull(store.createOrder());
    }
}
