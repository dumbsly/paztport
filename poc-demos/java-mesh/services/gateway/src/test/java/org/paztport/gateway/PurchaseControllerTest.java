// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import io.micrometer.observation.ObservationRegistry;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.intent.Intent;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.http.HttpCaller;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.outbound.OutboundInterceptor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

// The gateway is the origin: it states what the customer was shown as facts, which payment, two hops on, compares
// with the charge it is asked for. The client here stamps as the starter's does, so the facts are read from the
// origin's block as it goes on the wire.
class PurchaseControllerTest {

    private MockRestServiceServer orders;
    private PurchaseController controller;

    @BeforeEach
    void start() {
        Stamper stamper = new Stamper("gateway", "gateway-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> UUID.randomUUID().toString(), System::currentTimeMillis);
        HttpCaller caller = HttpCaller.builder("gateway", stamper)
                .extensions(ExtensionSettings.of(Set.of(Influence.NAME, Intent.NAME), null))
                .build();
        RestClient.Builder http = RestClient.builder()
                .requestInterceptor(new OutboundInterceptor(caller, ObservationRegistry.NOOP));
        orders = MockRestServiceServer.bindTo(http).build();
        controller = new PurchaseController(http.build(), new DemoTokens(Map.of("alice-token", "alice")),
                "https://orders:8080");
    }

    @Test
    void theGatewaySealsCustomerOrderAndAmount() {
        AtomicReference<String> blocks = new AtomicReference<>();
        orders.expect(requestTo("https://orders:8080/purchase")).andExpect(method(HttpMethod.POST))
                .andExpect(request -> blocks.set(request.getHeaders().getFirst(PaztportHeaders.EXTENSIONS)))
                .andExpect(content().json("{\"customer\":\"alice\",\"order\":\"123\",\"card\":\"4242 4242 4242 4242\"}",
                        true))
                .andRespond(withSuccess("{\"status\":\"CHARGED\"}", MediaType.APPLICATION_JSON));

        ResponseEntity<?> response;
        try (RequestContext.Scope scope = RequestContext.open()) {
            response = controller.purchase("Bearer alice-token",
                    new PurchaseController.Purchase("123", "4242 4242 4242 4242", 100L));
        }

        assertEquals(200, response.getStatusCode().value());
        orders.verify();
        assertNotNull(blocks.get(), "the call carries its blocks");
        List<Block> sent = Block.parseAll(HttpWire.decodeBlocks(blocks.get()));
        assertEquals(1, sent.size(), "the origin's block alone");
        assertEquals(List.of("{\"facts\":{\"amount\":100,\"customer\":\"alice\",\"order\":\"123\"}}"),
                sent.get(0).itemsUnder(Intent.NAME), "the customer from the token, the order and amount from the body");
    }

    // With no amount there is nothing for payment to compare a charge with, so the gateway sends nothing.
    @Test
    void aPurchaseWithNoAmountIsRefused() {
        assertRefused(new PurchaseController.Purchase("123", "4242 4242 4242 4242", null), "NO_AMOUNT");
    }

    // A fact's integer is from 0 to 2^53 - 1, so an amount outside that is no price the customer was shown, and it
    // is refused before anything is sealed or sent.
    @Test
    void anAmountNoFactCanHoldIsRefused() {
        assertRefused(new PurchaseController.Purchase("123", "4242 4242 4242 4242", -1L), "BAD_AMOUNT");
        assertRefused(new PurchaseController.Purchase("123", "4242 4242 4242 4242", 9_007_199_254_740_992L),
                "BAD_AMOUNT");
    }

    // The largest protocol integer is a price the gateway can state; orders then compares it with its book.
    @Test
    void theLargestProtocolIntegerIsSealed() {
        AtomicReference<String> blocks = new AtomicReference<>();
        orders.expect(requestTo("https://orders:8080/purchase"))
                .andExpect(request -> blocks.set(request.getHeaders().getFirst(PaztportHeaders.EXTENSIONS)))
                .andRespond(withSuccess("{\"status\":\"CHARGED\"}", MediaType.APPLICATION_JSON));

        try (RequestContext.Scope scope = RequestContext.open()) {
            controller.purchase("Bearer alice-token",
                    new PurchaseController.Purchase("123", "4242 4242 4242 4242", 9_007_199_254_740_991L));
        }

        orders.verify();
        assertEquals(List.of("{\"facts\":{\"amount\":9007199254740991,\"customer\":\"alice\",\"order\":\"123\"}}"),
                Block.parseAll(HttpWire.decodeBlocks(blocks.get())).get(0).itemsUnder(Intent.NAME));
    }

    // The card is not a fact, but a purchase without one is no purchase, so it is refused here rather than as a
    // charge payment cannot read.
    @Test
    void aPurchaseWithNoCardIsRefused() {
        assertRefused(new PurchaseController.Purchase("123", null, 100L), "NO_CARD");
        assertRefused(new PurchaseController.Purchase("123", " ", 100L), "NO_CARD");
    }

    /** Asserts {@code purchase} is answered {@code 400} with {@code reason}, and orders is not called. */
    private void assertRefused(PurchaseController.Purchase purchase, String reason) {
        ResponseEntity<?> response;
        try (RequestContext.Scope scope = RequestContext.open()) {
            response = controller.purchase("Bearer alice-token", purchase);
        }

        assertEquals(400, response.getStatusCode().value());
        assertEquals(Map.of("reason", reason), response.getBody());
        orders.verify();
    }
}
