// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.influence.Influence;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.spring.config.ModeHolder;
import org.paztport.spring.config.VerificationMode;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * The context's verified chain is set only by the result that decides attestation, so a later signer can trust it:
 * a chain that failed in audit, a hop that is off, an origin, and a forgery all leave it null.
 */
class VerifiedChainTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

    @AfterEach
    void cleanup() {
        PaztportContext.reset();
    }

    /** Captures, inside the handler, what the context says was verified. */
    private static final class Capture extends HttpServlet {
        List<StampV3> verified;
        List<StampV3> inbound;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) {
            verified = PaztportContext.verifiedChain();
            inbound = PaztportContext.inboundChain();
        }
    }

    private VerifierV3 verifier(KeyPair ordersKey) {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", ordersKey.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), policy.signedRoot().notAfter(),
                Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> NOW, 5000, 5000));
    }

    private InboundFilter filter(VerificationMode mode, boolean origin) {
        return new InboundFilter(verifier(orders), true, origin, "payment", new ModeHolder(mode),
                event -> { }, null, null);
    }

    private InboundFilter attestOnly() {
        return new InboundFilter(verifier(orders), false, false, "payment", null, null, null,
                new StamperV3("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW));
    }

    /** A chain gateway to orders to payment, the last stamp signed by {@code ordersKey}. */
    private MockHttpServletRequest request(KeyPair ordersKey) {
        StamperV3.Stamped gw = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        policy.bundles().get("gateway"));
        StamperV3.Stamped ord = new StamperV3("orders", "ord-1", ordersKey.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", BODY), List.of(),
                        policy.bundles().get("orders"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.addHeader(PaztportHeaders.CHAIN, HttpV3.encodeChain(ord.chain()));
        String proof = HttpV3.encodeProof(ord.proof());
        if (proof != null) {
            request.addHeader(PaztportHeaders.PROOF, proof);
        }
        String influence = HttpV3.encodeInfluence(List.of());
        if (influence != null) {
            request.addHeader(PaztportHeaders.INFLUENCE, influence);
        }
        request.setContent(BODY);
        return request;
    }

    private static MockHttpServletRequest forged() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.addHeader(PaztportHeaders.CHAIN, HttpV3.encodeChain(List.of(new StampV3("gateway", "gw-1", "rid-f",
                NOW, "", "payment", RequestBinding.compute("POST", "/pay", BODY), Influence.commit(List.of()), "",
                ""))));
        request.setContent(BODY);
        return request;
    }

    private Capture run(InboundFilter filter, MockHttpServletRequest request) throws Exception {
        Capture capture = new Capture();
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain(capture));
        return capture;
    }

    @Test
    void enforceOkMarks() throws Exception {
        Capture seen = run(filter(VerificationMode.ENFORCE, false), request(orders));
        assertNotNull(seen.verified);
        assertEquals(seen.inbound, seen.verified);
        assertEquals(2, seen.verified.size());
    }

    @Test
    void auditFailureDoesNotMark() throws Exception {
        // Signed by a key the keyring does not hold: audit serves it, but it did not verify.
        Capture seen = run(filter(VerificationMode.AUDIT, false), request(Crypto.generateEd25519KeyPair()));
        assertNotNull(seen.inbound, "the request was served");
        assertNull(seen.verified);
    }

    @Test
    void offDoesNotMark() throws Exception {
        Capture seen = run(filter(VerificationMode.OFF, false), request(orders));
        assertNotNull(seen.inbound);
        assertNull(seen.verified);
    }

    @Test
    void attestOnlyHopMarksOnlyWhenOk() throws Exception {
        Capture ok = run(attestOnly(), request(orders));
        assertNotNull(ok.verified);
        assertEquals(ok.inbound, ok.verified);

        Capture bad = run(attestOnly(), forged());
        assertNotNull(bad.inbound);
        assertNull(bad.verified);
    }

    @Test
    void originNeverMarks() throws Exception {
        Capture seen = run(filter(VerificationMode.ENFORCE, true), request(orders));
        assertNull(seen.verified);
    }

    @Test
    void scopeEndsClean() throws Exception {
        run(filter(VerificationMode.ENFORCE, false), request(orders));
        assertNull(PaztportContext.verifiedChain());
    }
}
