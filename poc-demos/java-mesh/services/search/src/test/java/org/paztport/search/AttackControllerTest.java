// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import io.micrometer.observation.ObservationRegistry;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.outbound.OutboundInterceptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

// Search forwards a chain it was handed through the starter's own interceptor, which appends search's stamp and
// block. Forwarded with the blocks it came with, the chain reaches the check its row names (rows 4, 8c, 9, 10);
// forwarded with one of them altered, it is check 9a's (row 4b).
class AttackControllerTest {

    private final Stamper gateway = new Stamper("gateway", "gateway-1", Crypto.generateEd25519KeyPair().getPrivate(),
            true, () -> UUID.randomUUID().toString(), System::currentTimeMillis);
    private final Stamper tickets = new Stamper("tickets", "tickets-1", Crypto.generateEd25519KeyPair().getPrivate(),
            false, () -> "unused", System::currentTimeMillis);
    private final Stamper search = new Stamper("search", "search-1", Crypto.generateEd25519KeyPair().getPrivate(),
            false, () -> "unused", System::currentTimeMillis);
    /** The gateway acts on influence, so its block names it with nothing added: not the empty block. */
    private final Block gatewayBlock = Influence.block(List.of(), List.of());

    private final StolenChainStore store = new StolenChainStore();
    private final AtomicReference<HttpHeaders> sent = new AtomicReference<>();

    /** Search's controller over a stamping client as search's own (it acts on no extension), and payment refusing. */
    private AttackController attacker(MockRestServiceServer[] payment) {
        RestClient.Builder stamped = RestClient.builder().requestInterceptor(
                new OutboundInterceptor(search, null, null, "search", ExtensionSettings.NONE,
                        ObservationRegistry.NOOP));
        payment[0] = MockRestServiceServer.bindTo(stamped).build();
        payment[0].expect(requestTo("http://payment/pay"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(request -> sent.set(request.getHeaders()))
                .andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"reason\":\"PATH_NOT_ALLOWED\"}"));
        return new AttackController(stamped.build(), RestClient.builder().build(), store, "http://payment",
                Crypto.generateEd25519KeyPair().getPrivate(), "search-1");
    }

    private List<Block> sentBlocks() {
        return Block.parseAll(HttpWire.decodeBlocks(sent.get().getFirst(PaztportHeaders.EXTENSIONS)));
    }

    private List<Stamp> sentChain() {
        return Chains.parse(HttpWire.decodeChain(sent.get().getFirst(PaztportHeaders.CHAIN))).stamps();
    }

    @Test
    void forwardStolenSendsTheStolenBlocks() {
        List<Stamp> stolen = gateway.next(null, "search", "bind", gatewayBlock, null).chain();
        store.record(stolen, List.of(gatewayBlock));
        // The chain and blocks the attack request itself came with, which the scope gets back after the call.
        List<Stamp> own = gateway.next(null, "search", "other", gatewayBlock, null).chain();
        List<Block> ownBlocks = List.of(gatewayBlock);
        MockRestServiceServer[] payment = new MockRestServiceServer[1];
        AttackController attacker = attacker(payment);

        ResponseEntity<String> response;
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(own, ownBlocks);
            response = attacker.forwardStolen();
            assertSame(own, RequestContext.inboundChain(), "the request's own chain is put back");
            assertEquals(ownBlocks, RequestContext.inboundBlocks(), "and its blocks with it");
        }
        payment[0].verify();

        assertEquals(403, response.getStatusCode().value(), "payment's answer is mirrored");
        List<Stamp> chain = sentChain();
        List<Block> blocks = sentBlocks();
        assertEquals(2, chain.size(), "the stolen stamp, then search's");
        assertEquals(stolen.get(0), chain.get(0), "the stolen chain is sent unchanged");
        assertEquals(2, blocks.size(), "one block per stamp");
        assertEquals(gatewayBlock.toJson(), blocks.get(0).toJson(), "the stolen block, byte for byte");
        assertEquals(Block.EMPTY, blocks.get(1), "search acts on nothing, so its own block is the empty one");
        for (int i = 0; i < chain.size(); i++) {
            assertEquals(chain.get(i).ext(), blocks.get(i).commit(), "block " + i + " is the one its stamp commits to");
        }
    }

    // Two stolen stamps, each block holding an entry, so altering every block, or the last stolen one, is told apart
    // from altering the gateway's alone, and an alteration that drops or reorders the gateway's entry is seen. The
    // live gateway's block holds none.
    @Test
    void forwardAlteredAltersOneBlockAndOnlyOne() {
        InfluenceEntry page = new InfluenceEntry(InfluenceClass.PUBLIC, "http:docs", "h0", null, null);
        Block gatewayPageBlock = Influence.block(List.of(page), List.of());
        InfluenceEntry ticket = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "h1", null, null);
        Block ticketsBlock = Influence.block(List.of(ticket), List.of());
        List<Stamp> fromGateway = gateway.next(null, "tickets", "bind", gatewayPageBlock, null).chain();
        List<Stamp> stolen = tickets.next(fromGateway, "search", "bind", ticketsBlock, null).chain();
        store.record(stolen, List.of(gatewayPageBlock, ticketsBlock));
        MockRestServiceServer[] payment = new MockRestServiceServer[1];
        AttackController attacker = attacker(payment);

        ResponseEntity<String> response;
        try (RequestContext.Scope scope = RequestContext.open()) {
            response = attacker.forwardAltered();
        }
        payment[0].verify();

        assertEquals(403, response.getStatusCode().value(), "payment's answer is mirrored");
        List<Stamp> chain = sentChain();
        List<Block> blocks = sentBlocks();
        assertEquals(3, chain.size(), "the two stolen stamps, then search's");
        assertEquals(stolen, chain.subList(0, 2), "the stolen chain is sent unchanged");
        assertEquals(3, blocks.size(), "one block per stamp");

        Block altered = blocks.get(0);
        assertEquals(gatewayPageBlock.names(), altered.names(), "the gateway's block names what it named");
        assertEquals(gatewayPageBlock.requires(), altered.requires(), "and requires what it required");
        List<String> added = new ArrayList<>(altered.itemsUnder(Influence.NAME));
        assertEquals(gatewayPageBlock.itemsUnder(Influence.NAME), added.subList(0, added.size() - 1),
                "the gateway's own items are kept, in order");
        assertEquals(gatewayPageBlock.itemsUnder(Influence.NAME).size() + 1, added.size(), "one influence entry added");
        InfluenceEntry.parse(added.get(added.size() - 1));
        assertNotEquals(chain.get(0).ext(), altered.commit(), "the gateway's stamp no longer commits to its block");

        assertEquals(ticketsBlock.toJson(), blocks.get(1).toJson(), "the other stolen block, byte for byte");
        assertEquals(chain.get(1).ext(), blocks.get(1).commit());
        assertEquals(Block.EMPTY, blocks.get(2), "search's own block, which the interceptor appends");
        assertEquals(chain.get(2).ext(), blocks.get(2).commit());
    }
}
