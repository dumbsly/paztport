// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.Keyring;
import org.paztport.core.MerkleLeaf;
import org.paztport.core.MerkleTree;
import org.paztport.core.PathChain;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;
import org.paztport.core.Verifier;
import org.paztport.core.VerifierConfig;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class InboundFilterTest {

    private static final long NOW = 1_000_000L;
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private final MerkleTree tree = MerkleTree.build(
            List.of(
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders/payment"),
                    new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")),
            8, "v1");
    private final SignedRoot signedRoot = SignedRoot.sign(tree.root(), "v1", policy.getPrivate());
    private final ProofBundle gatewayBundle = new ProofBundle("gateway", "v1",
            Map.of("gateway/orders", tree.proofFor("gateway/orders")));
    private final ProofBundle ordersBundle = new ProofBundle("orders", "v1",
            Map.of("gateway/orders/payment", tree.proofFor("gateway/orders/payment")));

    private final CollectingPublisher events = new CollectingPublisher();

    @AfterEach
    void cleanup() {
        PaztportContext.clear();
    }

    private Verifier paymentVerifier() {
        VerifierConfig cfg = VerifierConfig.pinned(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", orders.getPublic())),
                signedRoot, policy.getPublic(), Set.of("gateway"), 5000, "payment",
                new InMemoryNonceCache(), () -> NOW);
        return new Verifier(cfg);
    }

    private InboundFilter filter(VerificationMode mode, CaptureStore capture) {
        return new InboundFilter(paymentVerifier(), new ModeHolder(mode), events, capture);
    }

    private OutboundStamper.StampedHeaders validHeaders() {
        var gw = new OutboundStamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .stamp(null, "POST", "/orders", "{}".getBytes(), "orders", gatewayBundle);
        PathChain inbound = PathChain.decode(gw.chainHeader());
        return new OutboundStamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 0L)
                .stamp(inbound, "POST", "/pay", TO_PAYMENT, "payment", ordersBundle);
    }

    private MockHttpServletRequest paymentRequest(OutboundStamper.StampedHeaders h, byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.addHeader(PaztportHeaders.CHAIN, h.chainHeader());
        if (h.proofHeader() != null) {
            request.addHeader(PaztportHeaders.PROOF, h.proofHeader());
        }
        request.setContent(body);
        return request;
    }

    @Test
    void enforceValidRequestPassesThrough() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.ENFORCE, null).doFilter(paymentRequest(validHeaders(), TO_PAYMENT), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
        assertTrue(events.all.isEmpty(), "no event on success");
    }

    @Test
    void enforceTamperedBodyIsRejectedWith403AndPublishesNonAuditEvent() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(VerificationMode.ENFORCE, null)
                .doFilter(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes()), response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("BINDING_MISMATCH"));
        assertEquals(1, events.all.size());
        assertEquals("BINDING_MISMATCH", events.all.get(0).reason());
        assertEquals(false, events.all.get(0).audit());
        assertEquals("rid-1", events.all.get(0).rid());
    }

    @Test
    void enforceMissingHeadersAreRejectedWithChainMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setContent(TO_PAYMENT);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(VerificationMode.ENFORCE, null).doFilter(request, response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("CHAIN_MISSING"));
    }

    @Test
    void auditModePassesTamperedRequestButPublishesAuditEvent() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.AUDIT, null)
                .doFilter(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes()), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest(), "audit always passes through");
        assertEquals(1, events.all.size());
        assertEquals("BINDING_MISMATCH", events.all.get(0).reason());
        assertEquals(true, events.all.get(0).audit());
    }

    @Test
    void offModeSkipsVerificationEntirely() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setContent(TO_PAYMENT); // no headers at all
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.OFF, null).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
        assertTrue(events.all.isEmpty(), "off mode publishes nothing");
    }

    @Test
    void captureStoreRecordsTheReceivedRequestWhenEnabled() throws Exception {
        CaptureStore store = new CaptureStore();
        OutboundStamper.StampedHeaders h = validHeaders();

        filter(VerificationMode.ENFORCE, store)
                .doFilter(paymentRequest(h, TO_PAYMENT), new MockHttpServletResponse(), new MockFilterChain());

        assertTrue(store.last().isPresent());
        assertEquals(h.chainHeader(), store.last().get().chainHeader());
        assertEquals("/pay", store.last().get().path());
    }

    @Test
    void nonVerifyingFilterPopulatesContextAndProceeds() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        PathChain[] seen = new PathChain[1];
        HttpServlet capturing = new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse res) {
                seen[0] = PaztportContext.inboundChain();
            }
        };
        MockFilterChain chain = new MockFilterChain(capturing);

        new InboundFilter(null, null, null, null)
                .doFilter(paymentRequest(validHeaders(), TO_PAYMENT), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(seen[0]);
        assertEquals(2, seen[0].stamps().size());
    }

    @Test
    void managementPathsBypassVerification() throws Exception {
        // /admin and /debug are control plane: no headers, still must pass through.
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/mode");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.ENFORCE, null).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest(), "management path must reach the controller");
    }

    @Test
    void contextIsClearedAfterTheRequest() throws Exception {
        filter(VerificationMode.ENFORCE, null)
                .doFilter(paymentRequest(validHeaders(), TO_PAYMENT), new MockHttpServletResponse(), new MockFilterChain());

        org.junit.jupiter.api.Assertions.assertNull(PaztportContext.inboundChain());
    }

    private static final class CollectingPublisher implements EventPublisher {
        final List<AttestationEvent> all = new ArrayList<>();

        @Override
        public void publish(AttestationEvent event) {
            all.add(event);
        }
    }
}
