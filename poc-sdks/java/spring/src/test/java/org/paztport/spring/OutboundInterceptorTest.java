// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Chains;
import org.paztport.core.Crypto;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.RecordedStamp;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class OutboundInterceptorTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders"),
                    List.of("gateway", "search")), 4,
            Crypto.generateEd25519KeyPair().getPrivate());

    /** The headers of every request the mock server received. */
    private final List<HttpHeaders> sent = new ArrayList<>();

    @AfterEach
    void cleanup() {
        PaztportContext.clear();
    }

    private StamperV3 gatewayStamper() {
        return new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L);
    }

    private StamperV3 ordersStamper() {
        return new StamperV3("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 2000L);
    }

    /** A RestClient carrying the interceptor, against a mock server expecting one request to {@code uri}. */
    private RestClient client(OutboundInterceptor interceptor, String uri) {
        RestClient.Builder builder = RestClient.builder().requestInterceptor(interceptor);
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(uri)).andRespond(request -> {
            sent.add(request.getHeaders());
            return withSuccess().createResponse(request);
        });
        return builder.build();
    }

    private static List<StampV3> chainOf(HttpHeaders headers) {
        List<RecordedStamp> stamps = Chains.parse(HttpV3.decodeChain(headers.getFirst(PaztportHeaders.CHAIN)), false)
                .stamps();
        return stamps.stream().map(StampV3.class::cast).toList();
    }

    @Test
    void stampsForTheUriHostAndAttachesTheProof() {
        client(new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway")), "http://orders:8080/orders")
                .post().uri("http://orders:8080/orders").body("{}").retrieve().toBodilessEntity();

        List<StampV3> chain = chainOf(sent.get(0));
        assertEquals(1, chain.size());
        assertEquals("gateway", chain.get(0).svc());
        assertEquals("orders", chain.get(0).rcv());
        assertEquals("", chain.get(0).infl());
        assertNotNull(sent.get(0).getFirst(PaztportHeaders.PROOF), "proof for gateway/orders must be attached");
    }

    @Test
    void appendsToTheInboundChainCommittingTheContextInfluence() {
        StamperV3.Stamped received = gatewayStamper().next(null, "orders", "b", List.of(),
                policy.bundles().get("gateway"));
        PaztportContext.setInboundChain(received.chain());
        PaztportContext.addInfluence(MINE, WEB);

        client(new OutboundInterceptor(ordersStamper(), policy.bundles().get("orders")), "http://payment:8080/pay")
                .post().uri("http://payment:8080/pay").body("{\"amount\":1}").retrieve().toBodilessEntity();

        List<StampV3> chain = chainOf(sent.get(0));
        assertEquals(2, chain.size());
        StampV3 last = chain.get(1);
        assertEquals("orders", last.svc());
        assertEquals("payment", last.rcv());
        assertEquals(Influence.commit(List.of(MINE, WEB)), last.infl());
        assertEquals(RequestBinding.compute("POST", "/pay", "{\"amount\":1}".getBytes(StandardCharsets.UTF_8)),
                last.bind());
        assertEquals(List.of(MINE, WEB),
                Influence.parse(HttpV3.decodeInfluence(sent.get(0).getFirst(PaztportHeaders.INFLUENCE))));
        assertNotNull(sent.get(0).getFirst(PaztportHeaders.PROOF));
    }

    @Test
    void noInfluenceSendsNoInfluenceHeader() {
        client(new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway")), "http://orders:8080/orders")
                .post().uri("http://orders:8080/orders").body("{}").retrieve().toBodilessEntity();

        assertNull(sent.get(0).getFirst(PaztportHeaders.INFLUENCE));
    }

    @Test
    void omitsTheProofHeaderWhenNoneIsHeldForTheRoute() {
        // gateway -> payment is not a route gateway holds a proof for.
        client(new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway")), "http://payment:8080/pay")
                .post().uri("http://payment:8080/pay").body("{}").retrieve().toBodilessEntity();

        assertNull(sent.get(0).getFirst(PaztportHeaders.PROOF));
    }

    @Test
    void bindsTheRawQuery() {
        client(new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway")),
                "http://search:8080/search?q=a%20b")
                .get().uri("http://search:8080/search?q=a b").retrieve().toBodilessEntity();

        StampV3 stamp = chainOf(sent.get(0)).get(0);
        assertEquals("search", stamp.rcv());
        assertEquals(RequestBinding.compute("GET", "/search?q=a%20b", new byte[0]), stamp.bind());
    }

    @Test
    void bindsAnEncodedQueryAsSent() {
        URI uri = URI.create("http://search:8080/search?q=caf%C3%A9%20x");
        client(new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway")), uri.toString())
                .get().uri(uri).retrieve().toBodilessEntity();

        assertEquals(RequestBinding.compute("GET", "/search?q=caf%C3%A9%20x", new byte[0]),
                chainOf(sent.get(0)).get(0).bind());
    }
}
