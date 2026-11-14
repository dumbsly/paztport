// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.tickets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import io.micrometer.observation.ObservationRegistry;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.outbound.OutboundInterceptor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

// The ticket's text enters the request as third-party content before the assistant ever sees it: tickets acts on
// influence, so its own block on the call to the assistant carries the entry, decoded as the SDK's own interceptor
// wrote it, after the gateway's block forwarded unchanged.
class TicketsControllerTest {

    private static final String TEXT = "Order 123 arrived broken.";
    private static final ExtensionSettings INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);

    @Test
    void theTicketGoesToTheAssistantAsThirdPartyContent() {
        Stamper gateway = new Stamper("gateway", "gateway-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> UUID.randomUUID().toString(), System::currentTimeMillis);
        Stamper tickets = new Stamper("tickets", "tickets-1", Crypto.generateEd25519KeyPair().getPrivate(), false,
                () -> "unused", System::currentTimeMillis);
        // The gateway acts on influence too, so its block names it, with nothing it added itself.
        Block gatewayBlock = Influence.block(List.of(), List.of());
        List<Stamp> inbound = gateway.next(null, "tickets", "bind", gatewayBlock, null).chain();

        RestClient.Builder builder = RestClient.builder().requestInterceptor(
                new OutboundInterceptor(tickets, null, null, "tickets", INFLUENCE, ObservationRegistry.NOOP));
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        AtomicReference<String> blocksHeader = new AtomicReference<>();
        server.expect(requestTo("http://assistant/assist"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.ticket").value("t-1"))
                .andExpect(jsonPath("$.author").value("alice"))
                .andExpect(jsonPath("$.text").value(TEXT))
                .andExpect(request -> blocksHeader.set(request.getHeaders().getFirst(PaztportHeaders.EXTENSIONS)))
                .andRespond(withSuccess("{\"actions\":[{\"action\":\"email\",\"status\":200,\"result\":\"SENT\"}]}",
                        MediaType.APPLICATION_JSON));
        TicketsController controller = new TicketsController(builder.build(), "http://assistant");

        ResponseEntity<?> response;
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(inbound, List.of(gatewayBlock));
            response = controller.ticket(new TicketsController.Ticket("alice", TEXT));
        }
        server.verify();

        assertNotNull(blocksHeader.get(), "the call to the assistant carries its blocks");
        List<Block> blocks = Block.parseAll(HttpWire.decodeBlocks(blocksHeader.get()));
        assertEquals(2, blocks.size(), "the gateway's block, then tickets' own");
        assertEquals(gatewayBlock, blocks.get(0));
        List<String> items = blocks.get(1).itemsUnder(Influence.NAME);
        assertNotNull(items, "tickets' own block names influence");
        List<InfluenceEntry> influence = items.stream().map(InfluenceEntry::parse).toList();
        String hash = Base64Url.encode(Crypto.sha256(TEXT.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of(new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", hash, null, null)),
                influence);

        assertEquals(200, response.getStatusCode().value());
        assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
        // The ticket, its author and rid, and the assistant's actions as it wrote them, in that order.
        assertEquals("{\"ticket\":\"t-1\",\"author\":\"alice\",\"rid\":\"" + inbound.get(0).rid()
                + "\",\"actions\":[{\"action\":\"email\",\"status\":200,\"result\":\"SENT\"}]}",
                response.getBody());
    }
}
