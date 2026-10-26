// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.MerkleLeaf;
import org.paztport.core.MerkleTree;
import org.paztport.core.OutboundStamper;
import org.paztport.core.PathChain;
import org.paztport.core.ProofBundle;
import org.paztport.core.Stamp;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;

class OutboundInterceptorTest {

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();

    private final MerkleTree tree = MerkleTree.build(
            List.of(
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders/payment"),
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")),
            8, "v1");
    private final ProofBundle gatewayBundle = new ProofBundle("gateway", "v1",
            Map.of("gateway/orders", tree.proofFor("gateway/orders")));
    private final ProofBundle ordersBundle = new ProofBundle("orders", "v1",
            Map.of("gateway/orders/payment", tree.proofFor("gateway/orders/payment")));

    @AfterEach
    void cleanup() {
        PaztportContext.clear();
    }

    private OutboundStamper gatewayStamper() {
        return new OutboundStamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L);
    }

    private OutboundStamper ordersStamper() {
        return new OutboundStamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 0L);
    }

    /** Executes the interceptor against a mock request and returns the (mutated) request headers' values. */
    private MockClientHttpRequest run(OutboundInterceptor interceptor, URI uri, byte[] body) throws IOException {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.POST, uri);
        interceptor.intercept(request, body, (req, b) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK));
        return request;
    }

    @Test
    void setsChainAndProofHeadersDerivingTargetFromUriHost() throws Exception {
        OutboundInterceptor interceptor = new OutboundInterceptor(gatewayStamper(), gatewayBundle);
        MockClientHttpRequest request = run(interceptor, URI.create("http://orders:8080/orders"), "{}".getBytes());

        String chain = request.getHeaders().getFirst(PaztportHeaders.CHAIN);
        String proof = request.getHeaders().getFirst(PaztportHeaders.PROOF);

        List<Stamp> stamps = PathChain.decode(chain).stamps();
        assertEquals("gateway", stamps.get(0).svc());
        assertTrue(proof != null && !proof.isBlank(), "proof for gateway/orders must be attached");
    }

    @Test
    void appendsUsingTheInboundChainFromContext() throws Exception {
        // Simulate orders having received gateway's chain.
        MockClientHttpRequest gw = run(new OutboundInterceptor(gatewayStamper(), gatewayBundle),
                URI.create("http://orders:8080/orders"), "{}".getBytes());
        PathChain inbound = PathChain.decode(gw.getHeaders().getFirst(PaztportHeaders.CHAIN));
        PaztportContext.setInboundChain(inbound);

        MockClientHttpRequest request = run(new OutboundInterceptor(ordersStamper(), ordersBundle),
                URI.create("http://payment:8080/pay"), "{\"amount\":1}".getBytes(StandardCharsets.UTF_8));

        List<Stamp> stamps = PathChain.decode(request.getHeaders().getFirst(PaztportHeaders.CHAIN)).stamps();
        assertEquals(2, stamps.size());
        assertEquals("orders", stamps.get(1).svc());
        assertTrue(request.getHeaders().getFirst(PaztportHeaders.PROOF) != null);
    }

    @Test
    void omitsProofHeaderWhenNoneHeldForTheRoute() throws Exception {
        OutboundInterceptor interceptor = new OutboundInterceptor(gatewayStamper(), gatewayBundle);
        // gateway -> payment is not a route gateway holds a proof for.
        MockClientHttpRequest request = run(interceptor, URI.create("http://payment:8080/pay"), "{}".getBytes());

        assertNull(request.getHeaders().getFirst(PaztportHeaders.PROOF));
    }

    @Test
    void callsThroughToTheExecution() throws Exception {
        OutboundInterceptor interceptor = new OutboundInterceptor(gatewayStamper(), gatewayBundle);
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://orders:8080/o"));
        ClientHttpResponse response = interceptor.intercept(
                request, "{}".getBytes(), (req, b) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
