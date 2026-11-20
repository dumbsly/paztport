// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.OriginIntent;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

// The attack endpoints sign as orders and send payment calls no honest orders makes, so nothing of them may exist
// unless the demo turns them on. When on, a steered call carries the blocks the stolen chain came with, so payment
// refuses it at the check its row names, not at check 9a. An armed change to a charge is the same code, inside the
// honest purchase.
class AttackControllerTest {

    /** The validity window of the fixture root: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(AttackController.class, StolenChainStore.class, ChargeTamper.class);

    @Test
    void theAttackEndpointsAreOffByDefault() {
        context.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(AttackController.class);
            assertThat(ctx).doesNotHaveBean(StolenChainStore.class);
            assertThat(ctx).doesNotHaveBean(ChargeTamper.class);
        });
    }

    // The condition is the property, not a class that is never registered: enabled, the store and the tamper are
    // there.
    @Test
    void enablingThemCreatesTheStore() {
        new ApplicationContextRunner()
                .withUserConfiguration(StolenChainStore.class, ChargeTamper.class)
                .withPropertyValues("attack.enabled=true")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(StolenChainStore.class);
                    assertThat(ctx).hasSingleBean(ChargeTamper.class);
                });
    }

    // In through getOrder, as row 15a: the store keeps the blocks orders was handed beside the chain, and the steered
    // call sends them unchanged, then the block orders signs, each block the one its stamp commits to.
    @Test
    void steerSendsTheStolenBlocksThenItsOwn() {
        PolicyBuilder.Result policy = PolicyBuilder.build(
                List.of(List.of("gateway", "orders#createOrder", "payment#pay"), List.of("gateway", "orders#getOrder")),
                4, NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());
        Stamper gateway = new Stamper("gateway", "gateway-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> UUID.randomUUID().toString(), System::currentTimeMillis);
        Stamper orders = new Stamper("orders", "orders-1", Crypto.generateEd25519KeyPair().getPrivate(), false,
                () -> "unused", System::currentTimeMillis);
        // The gateway's block holds an entry, where the live gateway's holds none, so a steer that sent orders' own
        // block in its place, or a copy of it as orders' own, is told apart from one that sends each where it belongs.
        InfluenceEntry ticket = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", null, null);
        Block gatewayBlock = Influence.block(List.of(ticket), List.of());
        List<Stamp> stolen = gateway.next(null, "orders#getOrder", "bind", gatewayBlock, null).chain();

        StolenChainStore store = new StolenChainStore();
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("stolenChains", store);
        OrdersController honest = new OrdersController(RestClient.builder().build(), new OrderBook(),
                "http://payment", beans.getBeanProvider(StolenChainStore.class), new OriginIntent("orders"),
                beans.getBeanProvider(ChargeTamper.class));
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(stolen, List.of(gatewayBlock));
            honest.byId("123");
        }

        RestClient.Builder raw = RestClient.builder();
        MockRestServiceServer payment = MockRestServiceServer.bindTo(raw).build();
        AtomicReference<HttpHeaders> sent = new AtomicReference<>();
        payment.expect(requestTo("http://payment/pay"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(request -> sent.set(request.getHeaders()))
                .andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"reason\":\"PATH_NOT_ALLOWED\"}"));
        AttackController attack = new AttackController(orders, policy.bundles().get("orders"), store,
                "http://payment", raw.build(), new ChargeTamper());

        ResponseEntity<String> response = attack.steerPay();
        payment.verify();

        assertEquals(403, response.getStatusCode().value(), "payment's answer is mirrored");
        assertEquals("{\"reason\":\"PATH_NOT_ALLOWED\"}", response.getBody());
        String blocksHeader = sent.get().getFirst(PaztportHeaders.EXTENSIONS);
        assertNotNull(blocksHeader, "the steered call carries its blocks");
        List<Block> blocks = Block.parseAll(HttpWire.decodeBlocks(blocksHeader));
        List<Stamp> chain = Chains.parse(HttpWire.decodeChain(sent.get().getFirst(PaztportHeaders.CHAIN))).stamps();
        assertEquals(2, chain.size(), "the stolen stamp, then orders' own");
        assertEquals(stolen.get(0), chain.get(0), "the stolen chain is sent unchanged");
        assertEquals(2, blocks.size(), "one block per stamp");
        assertEquals(gatewayBlock.toJson(), blocks.get(0).toJson(), "the stolen block, byte for byte");
        assertEquals(Influence.block(List.of(), List.of()), blocks.get(1),
                "orders acts on influence, so its block names it with nothing added");
        for (int i = 0; i < chain.size(); i++) {
            assertEquals(chain.get(i).ext(), blocks.get(i).commit(), "block " + i + " is the one its stamp commits to");
        }
    }

    // As row 17a: the code changes the amount of the next charge orders sends, after orders compared the facts with
    // its order book. The change is spent on that charge; the next goes as orders built it.
    @Test
    void anArmedAmountChangesOneChargeOnly() {
        ChargeTamper tamper = new ChargeTamper();
        AttackController attack = new AttackController(null, null, new StolenChainStore(), "http://payment",
                RestClient.builder().build(), tamper);
        RestClient.Builder http = RestClient.builder();
        MockRestServiceServer payment = MockRestServiceServer.bindTo(http).build();
        for (long amount : new long[] {9900, 100}) {
            payment.expect(requestTo("http://payment/charge")).andExpect(method(HttpMethod.POST))
                    .andExpect(content().string("{\"customer\":\"alice\",\"order\":\"123\","
                            + "\"card\":\"4242 4242 4242 4242\",\"amount\":" + amount + "}"))
                    .andRespond(withSuccess("{\"status\":\"CHARGED\"}", MediaType.APPLICATION_JSON));
        }
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("tamper", tamper);
        OrdersController orders = new OrdersController(http.build(), new OrderBook(), "http://payment",
                beans.getBeanProvider(StolenChainStore.class), new OriginIntent("orders"),
                beans.getBeanProvider(ChargeTamper.class));

        assertEquals(200, attack.alterAmount().getStatusCode().value());
        for (int i = 0; i < 2; i++) {
            OriginFacts.servedWith(OriginFacts.alicePays(100), () -> orders.purchase(
                    new OrdersController.Purchase("alice", "123", "4242 4242 4242 4242")));
        }

        payment.verify();
    }
}
