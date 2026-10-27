// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.tickets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.spring.OutboundInterceptor;
import org.paztport.spring.PaztportContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

// The ticket's text enters the request as third-party content before the assistant ever sees it: the influence
// header on the call to the assistant is decoded as the SDK's own interceptor wrote it.
class TicketsControllerTest {

    private static final String TEXT = "Order 123 arrived broken.";

    @Test
    void theTicketGoesToTheAssistantAsThirdPartyContent() {
        StamperV3 gateway = new StamperV3("gateway", "gateway-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> UUID.randomUUID().toString(), System::currentTimeMillis);
        StamperV3 tickets = new StamperV3("tickets", "tickets-1", Crypto.generateEd25519KeyPair().getPrivate(), false,
                () -> "unused", System::currentTimeMillis);
        List<StampV3> inbound = gateway.next(null, "tickets", "bind", List.of(), null).chain();

        RestClient.Builder builder = RestClient.builder()
                .requestInterceptor(new OutboundInterceptor(tickets, null, null, "tickets"));
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        AtomicReference<String> influenceHeader = new AtomicReference<>();
        server.expect(requestTo("http://assistant/assist"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.ticket").value("t-1"))
                .andExpect(jsonPath("$.author").value("alice"))
                .andExpect(jsonPath("$.text").value(TEXT))
                .andExpect(request -> influenceHeader.set(request.getHeaders().getFirst(PaztportHeaders.INFLUENCE)))
                .andRespond(withSuccess("{\"actions\":[{\"action\":\"email\",\"status\":200,\"result\":\"SENT\"}]}",
                        MediaType.APPLICATION_JSON));
        TicketsController controller = new TicketsController(builder.build(), "http://assistant");

        ResponseEntity<?> response;
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.setInboundChain(inbound);
            response = controller.ticket(new TicketsController.Ticket("alice", TEXT));
        }
        server.verify();

        assertNotNull(influenceHeader.get(), "the call to the assistant carries influence");
        List<InfluenceEntry> influence = Influence.parse(HttpV3.decodeInfluence(influenceHeader.get()));
        String hash = Base64Url.encode(Crypto.sha256(TEXT.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of(new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", hash, null, null)),
                influence);

        assertEquals(200, response.getStatusCode().value());
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        assertEquals("t-1", body.get("ticket"));
        assertEquals("alice", body.get("author"));
        assertEquals(inbound.get(0).rid(), body.get("rid"));
        assertEquals("[{\"action\":\"email\",\"status\":200,\"result\":\"SENT\"}]", body.get("actions").toString());
    }
}
