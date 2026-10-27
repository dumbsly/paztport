// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Bindings;
import org.paztport.core.Chains;
import org.paztport.core.ContentLabel;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.Keyring;
import org.paztport.core.Peer;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.ReasonCode;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;
import org.paztport.core.VerifyResult;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

class InboundFilterTest {

    private static final long NOW = 1_000_000L;
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders")), 4,
            Crypto.generateEd25519KeyPair().getPrivate());

    private final CollectingPublisher events = new CollectingPublisher();
    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

    @BeforeEach
    void captureTraces() {
        traces.start();
        traceLog.addAppender(traces);
        traceLog.setLevel(Level.INFO);
        traceLog.setAdditive(false);
    }

    @AfterEach
    void cleanup() {
        traceLog.detachAppender(traces);
        traceLog.setLevel(null);
        traceLog.setAdditive(true);
        PaztportContext.reset();
    }

    private VerifierV3 paymentVerifier() {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", orders.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> NOW, 5000, 5000));
    }

    private InboundFilter filter(VerificationMode mode, ReceivedRequestListener listener) {
        return new InboundFilter(paymentVerifier(), true, false, "payment", new ModeHolder(mode), events, listener,
                null);
    }

    /** A hop that neither verifies requests nor holds a verifier or a stamp key. */
    private static InboundFilter plainFilter() {
        return new InboundFilter(null, false, false, "payment", null, null, null, null);
    }

    private StamperV3 paymentStamper() {
        return new StamperV3("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW);
    }

    /** Payment verifying requests and holding a stamp key, so it attests what it answers to a verified chain. */
    private InboundFilter attestingFilter(VerifierV3 verifier, VerificationMode mode) {
        return new InboundFilter(verifier, true, false, "payment", new ModeHolder(mode), events, null,
                paymentStamper());
    }

    /**
     * Payment not verifying requests ({@code paztport.verify=false}) but holding a verifier and a stamp key, as
     * orders and search do in the mesh: it checks a chain only to decide whether to attest.
     */
    private InboundFilter nonEnforcingFilter(VerifierV3 verifier) {
        return new InboundFilter(verifier, false, false, "payment", null, null, null, paymentStamper());
    }

    /** A one-stamp chain claiming to come from the origin {@code gateway}, for {@code payment}, under {@code sig}. */
    private static String forgedChain(String rid, String sig) {
        return HttpV3.encodeChain(List.of(new StampV3("gateway", "gw-1", rid, NOW, "", "payment",
                RequestBinding.compute("POST", "/pay", TO_PAYMENT), Influence.commit(List.of()), "", sig)));
    }

    /** The two forgeries anyone can write without a key: an empty signature, and well-formed garbage. */
    private static final List<String> FORGED_SIGS = List.of("", Base64Url.encode(new byte[64]));

    private record Headers(String chain, String proof, String influence) {
    }

    private Headers headers(String rid, String target, List<InfluenceEntry> influence) {
        StamperV3.Stamped gw = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        policy.bundles().get("gateway"));
        StamperV3.Stamped ord = new StamperV3("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", target, TO_PAYMENT), influence,
                        policy.bundles().get("orders"));
        return new Headers(HttpV3.encodeChain(ord.chain()), HttpV3.encodeProof(ord.proof()),
                HttpV3.encodeInfluence(influence));
    }

    private Headers validHeaders() {
        return headers("rid-1", "/pay", List.of());
    }

    private MockHttpServletRequest paymentRequest(Headers h, byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        if (h.chain() != null) {
            request.addHeader(PaztportHeaders.CHAIN, h.chain());
        }
        if (h.proof() != null) {
            request.addHeader(PaztportHeaders.PROOF, h.proof());
        }
        if (h.influence() != null) {
            request.addHeader(PaztportHeaders.INFLUENCE, h.influence());
        }
        request.setContent(body);
        return request;
    }

    /** A handler that records what the context held while the request was served. */
    private static final class Seen extends HttpServlet {
        List<StampV3> chain;
        List<InfluenceEntry> influence;
        boolean reached;
        boolean scoped;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) {
            reached = true;
            scoped = PaztportContext.isOpen();
            chain = PaztportContext.inboundChain();
            influence = PaztportContext.influence();
        }
    }

    /** A handler that labels what it answers, as a service serving alice's data would. */
    private static final class Answering extends HttpServlet {
        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
            res.setStatus(201);
            res.getOutputStream().write("paid".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static JsonNode decodeAttestation(MockHttpServletResponse response) {
        return HttpV3.decodeChain(response.getHeader(PaztportHeaders.RESPONSE));
    }

    private List<String> traceLines() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void enforceValidRequestPassesThroughWithTheVerifiedInfluence() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(MINE, WEB)), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(200, response.getStatus());
        assertTrue(seen.reached);
        assertEquals(2, seen.chain.size());
        assertEquals(List.of(MINE, WEB), seen.influence);
        assertTrue(events.all.isEmpty(), "no event on success");
    }

    @Test
    void theQueryIsPartOfTheBoundTarget() throws Exception {
        MockHttpServletRequest bound = paymentRequest(headers("rid-1", "/pay?id=7", List.of()), TO_PAYMENT);
        bound.setQueryString("id=7");
        MockHttpServletResponse ok = new MockHttpServletResponse();
        filter(VerificationMode.ENFORCE, null).doFilter(bound, ok, new MockFilterChain());
        assertEquals(200, ok.getStatus());

        MockHttpServletRequest other = paymentRequest(headers("rid-2", "/pay?id=7", List.of()), TO_PAYMENT);
        other.setQueryString("id=8");
        MockHttpServletResponse rejected = new MockHttpServletResponse();
        filter(VerificationMode.ENFORCE, null).doFilter(other, rejected, new MockFilterChain());
        assertEquals(403, rejected.getStatus());
        assertTrue(rejected.getContentAsString().contains("BINDING_MISMATCH"));
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
    void enforceAlteredInfluenceIsRejectedWithInfluenceMismatch() throws Exception {
        Headers h = headers("rid-1", "/pay", List.of(MINE));
        Headers altered = new Headers(h.chain(), h.proof(), HttpV3.encodeInfluence(List.of(WEB)));
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        filter(VerificationMode.ENFORCE, null).doFilter(paymentRequest(altered, TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("INFLUENCE_MISMATCH"));
        assertEquals("INFLUENCE_MISMATCH", events.all.get(0).reason());
        assertTrue(!seen.reached);
    }

    @Test
    void enforceMissingHeadersAreRejectedWithChainMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setContent(TO_PAYMENT);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(VerificationMode.ENFORCE, null).doFilter(request, response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("CHAIN_MISSING"));
        assertEquals("CHAIN_MISSING", events.all.get(0).reason());
    }

    @Test
    void auditModePassesTamperedRequestWithTheReceivedInfluence() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        filter(VerificationMode.AUDIT, null).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(MINE)), "{\"amount\":999}".getBytes()), response,
                new MockFilterChain(seen));

        assertEquals(200, response.getStatus());
        assertTrue(seen.reached, "audit always passes through");
        assertEquals(List.of(MINE), seen.influence, "what was received still counts towards the rule");
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
        assertTrue(traceLines().isEmpty(), "and verifies nothing, so traces nothing");
    }

    @Test
    void aRegisteredListenerIsCalledOncePerRequestWithTheReceivedValues() throws Exception {
        List<Object[]> calls = new ArrayList<>();
        Headers h = headers("rid-1", "/pay", List.of(WEB));
        MockHttpServletRequest request = paymentRequest(h, TO_PAYMENT);
        request.setQueryString("id=7");

        filter(VerificationMode.ENFORCE, (chain, proof, influence, method, target, body) ->
                calls.add(new Object[] {chain, proof, influence, method, target, body}))
                .doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(1, calls.size());
        Object[] call = calls.get(0);
        assertEquals(h.chain(), call[0]);
        assertEquals(h.proof(), call[1]);
        assertEquals(h.influence(), call[2]);
        assertEquals("POST", call[3]);
        assertEquals("/pay?id=7", call[4]);
        assertArrayEquals(TO_PAYMENT, (byte[]) call[5]);
    }

    @Test
    void theListenerSeesARequestThatVerificationThenRejects() throws Exception {
        List<String> order = new ArrayList<>();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(VerificationMode.ENFORCE, (chain, proof, influence, method, target, body) -> order.add("listener"))
                .doFilter(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)),
                        response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertEquals(List.of("listener"), order, "called before verification, even for a request that fails it");
    }

    @Test
    void nonVerifyingFilterPopulatesContextFromTheHeadersAndProceeds() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        plainFilter().doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(200, response.getStatus());
        assertEquals(2, seen.chain.size());
        assertEquals("rid-1", seen.chain.get(0).rid());
        assertEquals(List.of(WEB), seen.influence);
        assertTrue(traceLines().isEmpty(), "nothing was verified");
    }

    @Test
    void nonVerifyingFilterAnswersMalformedInfluenceWith400() throws Exception {
        Headers h = validHeaders();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        plainFilter().doFilter(
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(400, response.getStatus());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", response.getContentAsString());
        assertTrue(!seen.reached, "influence that cannot be carried must not be dropped");
    }

    @Test
    void anUnreadableChainLeavesNoInboundChain() throws Exception {
        Seen seen = new Seen();

        plainFilter().doFilter(
                paymentRequest(new Headers("not-a-chain", null, null), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain(seen));

        assertTrue(seen.reached);
        assertNull(seen.chain);
    }

    @Test
    void everyVerificationLogsOneTraceLine() throws Exception {
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB, MINE)), TO_PAYMENT),
                new MockHttpServletResponse(), new MockFilterChain());
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("rid-2", "/pay", List.of()), "{}".getBytes()),
                new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=private,third-party",
                "PAZTPORT_TRACE request rid=rid-2 reason=BINDING_MISMATCH receiver=payment ✗ peer=none classes=-"),
                traceLines());
    }

    @Test
    void theTraceLineKeepsAForgedRidOnOneLine() throws Exception {
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("r\nPAZTPORT_TRACE request reason=OK", "/pay", List.of()), TO_PAYMENT),
                new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(1, traceLines().size());
        assertTrue(traceLines().get(0).startsWith("PAZTPORT_TRACE request rid=r\\u000aPAZTPORT_TRACE"),
                traceLines().get(0));
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
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain());

        assertNull(PaztportContext.inboundChain());
        assertTrue(PaztportContext.influence().isEmpty());
    }

    /** Two endpoints: one dirties the context, the other reports what it found. */
    @RestController
    static final class ReuseController {
        List<StampV3> chain;
        List<InfluenceEntry> influence;
        List<ContentLabel> labels;

        @PostMapping("/dirty")
        String dirty() {
            PaztportContext.addInfluence(WEB);
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
            return "ok";
        }

        @PostMapping("/look")
        String look() {
            chain = PaztportContext.inboundChain();
            influence = PaztportContext.influence();
            labels = PaztportContext.labels();
            return "ok";
        }
    }

    @Test
    void threadReuseStartsClean() throws Exception {
        ReuseController controller = new ReuseController();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .addFilters(plainFilter())
                .build();
        Headers first = headers("rid-1", "/pay", List.of(MINE));
        Headers second = headers("rid-2", "/pay", List.of());

        // MockMvc serves both on this test thread, as a pooled server thread would serve two requests.
        mvc.perform(post("/dirty").header(PaztportHeaders.CHAIN, first.chain())
                        .header(PaztportHeaders.INFLUENCE, first.influence()).content(TO_PAYMENT))
                .andExpect(status().isOk());
        mvc.perform(post("/look").header(PaztportHeaders.CHAIN, second.chain()).content(TO_PAYMENT))
                .andExpect(status().isOk());

        assertEquals("rid-2", controller.chain.get(0).rid());
        assertEquals(2, controller.chain.size());
        assertEquals(List.of(), controller.influence);
        assertEquals(List.of(), controller.labels);
    }

    private static final class CollectingPublisher implements EventPublisher {
        final List<AttestationEvent> all = new ArrayList<>();

        @Override
        public void publish(AttestationEvent event) {
            all.add(event);
        }
    }

    @Test
    void theRefusalBodyIsJsonWhateverTheSuspectSigned() throws Exception {
        String inst = "ord\"1\\";
        StamperV3.Stamped gw = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .next(null, "orders", "b", List.of(), policy.bundles().get("gateway"));
        StamperV3.Stamped ord = new StamperV3("orders", inst, orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), List.of(),
                        policy.bundles().get("orders"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        // No proof, so the route is unproven and the last signer, with its chosen inst, is the suspect.
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(new Headers(HttpV3.encodeChain(ord.chain()), null, null), TO_PAYMENT),
                response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        JsonNode body = new ObjectMapper().readTree(response.getContentAsString());
        assertEquals("PATH_NOT_ALLOWED", body.get("reason").textValue());
        assertEquals("orders", body.get("suspectSvc").textValue());
        assertEquals(inst, body.get("suspectInst").textValue());
        assertEquals("{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"orders\",\"suspectInst\":\"ord\\\"1\\\\\"}",
                response.getContentAsString(), "same fields, same order, properly escaped");
    }

    @Test
    void auditAndOffModesStillAnswerMalformedInfluenceWith400() throws Exception {
        Headers h = validHeaders();
        for (VerificationMode mode : List.of(VerificationMode.AUDIT, VerificationMode.OFF)) {
            for (InboundFilter hop : List.of(filter(mode, null), attestingFilter(paymentVerifier(), mode))) {
                MockHttpServletResponse response = new MockHttpServletResponse();
                Seen seen = new Seen();

                hop.doFilter(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT),
                        response, new MockFilterChain(seen));

                assertEquals(400, response.getStatus(), mode.name());
                assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", response.getContentAsString(), mode.name());
                assertTrue(!seen.reached, mode + ": influence that cannot be read is never dropped");
            }
        }
    }

    /**
     * {@code OFF} on a verifier is the operator turning Paztport off on that hop: nothing is checked, so nothing is
     * vouched for, even for a chain that would verify. What the handler is given is unchanged, so its own calls are
     * stamped as before.
     */
    @Test
    void aVerifierSwitchedOffVerifiesNothingAndAttestsNothing() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        attestingFilter(paymentVerifier(), VerificationMode.OFF).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), response,
                new MockFilterChain(new Answering()));
        attestingFilter(paymentVerifier(), VerificationMode.OFF).doFilter(
                paymentRequest(headers("rid-2", "/pay", List.of(WEB)), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain(seen));

        assertEquals(201, response.getStatus());
        assertEquals("paid", response.getContentAsString(), "served as before");
        assertNull(response.getHeader(PaztportHeaders.RESPONSE), "a chain that would verify, but nothing checked it");
        assertTrue(traceLines().isEmpty(), "no verification ran, not even one for attestation alone");
        assertTrue(events.all.isEmpty());
        assertEquals(2, seen.chain.size(), "the inbound chain is carried for outbound stamping");
        assertEquals(List.of(WEB), seen.influence, "and so is the influence received");
    }

    @Test
    void switchingAVerifierOffAndBackAtRuntimeTakesEffectOnTheNextRequest() throws Exception {
        ModeHolder mode = new ModeHolder(VerificationMode.ENFORCE);
        InboundFilter hop = new InboundFilter(paymentVerifier(), true, false, "payment", mode, events, null,
                paymentStamper());
        List<Boolean> attested = new ArrayList<>();
        int rid = 0;
        for (VerificationMode next : List.of(VerificationMode.ENFORCE, VerificationMode.OFF,
                VerificationMode.ENFORCE, VerificationMode.OFF)) {
            mode.set(next);
            MockHttpServletResponse response = new MockHttpServletResponse();
            hop.doFilter(paymentRequest(headers("rid-" + ++rid, "/pay", List.of()), TO_PAYMENT), response,
                    new MockFilterChain(new Answering()));
            assertEquals("paid", response.getContentAsString(), next.name());
            attested.add(response.getHeader(PaztportHeaders.RESPONSE) != null);
        }

        assertEquals(List.of(true, false, true, false), attested);
        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=-",
                "PAZTPORT_TRACE request rid=rid-3 reason=OK receiver=payment ✓ peer=none classes=-"),
                traceLines(), "verified only while enforcing");
    }

    @Test
    void aVerifiedRequestsResponseIsAttestedOverWhatTheHandlerSent() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                paymentRequest(validHeaders(), TO_PAYMENT), response, new MockFilterChain(new Answering()));

        assertEquals(201, response.getStatus());
        assertEquals("paid", response.getContentAsString(), "the body still reaches the caller");
        JsonNode attestation = decodeAttestation(response);
        List<ContentLabel> labels = ContentLabel.parseAll(attestation.get("labels"));
        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        StampV3 stamp = (StampV3) Chains.parse(
                new ObjectMapper().createArrayNode().add(attestation.get("stamp")), false).stamps().get(0);
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv(), "the response goes back to whoever called");
        assertEquals("rid-1", stamp.rid());
        assertEquals(Bindings.response(HttpV3.resultHash(201, "paid".getBytes(StandardCharsets.UTF_8)), "rid-1",
                labels), stamp.bind());
    }

    @Test
    void aVerifiedRequestIsVerifiedOnceForBothTheModeAndTheAttestation() throws Exception {
        attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                paymentRequest(validHeaders(), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain(new Answering()));

        // A second run would spend the request's nonce again and come back REPLAY.
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=-"),
                traceLines());
    }

    @Test
    void aServiceThatDoesNotVerifyRequestsAttestsAChainThatVerifiesHere() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        nonEnforcingFilter(paymentVerifier()).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), response,
                new MockFilterChain(new Answering()));
        nonEnforcingFilter(paymentVerifier()).doFilter(
                paymentRequest(headers("rid-2", "/pay", List.of(WEB)), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain(seen));

        assertEquals("paid", response.getContentAsString());
        StampV3 stamp = (StampV3) Chains.parse(new ObjectMapper().createArrayNode()
                .add(decodeAttestation(response).get("stamp")), false).stamps().get(0);
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv());
        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=third-party",
                "PAZTPORT_TRACE request rid=rid-2 reason=OK receiver=payment ✓ peer=none classes=third-party"),
                traceLines(), "checked once each, for attestation alone");
        assertEquals(List.of(WEB), seen.influence, "the influence is carried as before");
        assertEquals(2, seen.chain.size());
    }

    /**
     * A response stamp is request-shaped: on a one-stamp chain, it would be a valid origin stamp from this service.
     * So a forged chain, which anyone can write, must never be attested, whether or not the hop enforces.
     */
    @Test
    void aForgedChainIsNeverAttestedButStillServedWhereRequestsAreNotVerified() throws Exception {
        for (String sig : FORGED_SIGS) {
            for (InboundFilter hop : List.of(nonEnforcingFilter(paymentVerifier()),
                    attestingFilter(paymentVerifier(), VerificationMode.OFF))) {
                MockHttpServletResponse response = new MockHttpServletResponse();

                hop.doFilter(paymentRequest(new Headers(forgedChain("rid-" + sig, sig), null, null), TO_PAYMENT),
                        response, new MockFilterChain(new Answering()));

                assertEquals("paid", response.getContentAsString(), "sig=\"" + sig + "\": not refused");
                assertNull(response.getHeader(PaztportHeaders.RESPONSE), "sig=\"" + sig + "\": nothing minted");
            }
        }
        assertTrue(events.all.isEmpty(), "checking for attestation publishes nothing");
        // Only the hop that does not verify requests checks the chain; the one switched off checks nothing.
        assertEquals(2, traceLines().size());
        for (String line : traceLines()) {
            assertTrue(line.contains(" reason=BAD_SIGNATURE receiver=payment ✗ "), line);
        }
    }

    /**
     * The attack this guards against: a compromised service sends the origin a forged one-stamp chain naming
     * another service as its sender. Were it attested, the origin's response stamp would be a genuine origin stamp
     * addressed to that service, ready to start a chain it never sent. The origin attests nothing, so there is no
     * stamp to drive the next hop with.
     */
    @Test
    void anOriginNeverAttestsAForgedChain() throws Exception {
        StamperV3 gatewayStamper = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "r", () -> NOW);
        for (String sig : FORGED_SIGS) {
            String forged = HttpV3.encodeChain(List.of(new StampV3("orders", "x", "R", NOW, "", "x", "b",
                    Influence.commit(List.of()), "", sig)));
            for (VerifierV3 verifier : Arrays.asList(null, paymentVerifier())) {
                MockHttpServletRequest request = new MockHttpServletRequest("GET", "/find");
                request.addHeader(PaztportHeaders.CHAIN, forged);
                MockHttpServletResponse response = new MockHttpServletResponse();

                new InboundFilter(verifier, false, true, "gateway", null, null, null, gatewayStamper)
                        .doFilter(request, response, new MockFilterChain(new Answering()));

                assertEquals("paid", response.getContentAsString());
                assertNull(response.getHeader(PaztportHeaders.RESPONSE), "sig=\"" + sig + "\": nothing minted");
            }
        }
    }

    @Test
    void anOriginNeverAttestsAndStartsFromNothingEvenWhenTheChainVerifies() throws Exception {
        StamperV3 ordersAsOrigin = new StamperV3("orders", "ord-1", orders.getPrivate(), true, () -> "r", () -> NOW);
        for (boolean verify : new boolean[] {true, false}) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            Seen seen = new Seen();
            new InboundFilter(paymentVerifier(), verify, true, "payment",
                    new ModeHolder(VerificationMode.ENFORCE), events, null, ordersAsOrigin).doFilter(
                    paymentRequest(headers("rid-" + verify, "/pay", List.of(MINE)), TO_PAYMENT), response,
                    new MockFilterChain(seen));

            assertTrue(seen.reached, "verify=" + verify);
            assertNull(seen.chain, "verify=" + verify + ": an origin starts a new tree");
            assertEquals(List.of(), seen.influence, "verify=" + verify + ": and carries no influence it was sent");
            assertNull(response.getHeader(PaztportHeaders.RESPONSE), "verify=" + verify);
        }
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-true reason=OK receiver=payment ✓ peer=none "
                + "classes=private"), traceLines(), "verified under the mode, and not again for attestation");
    }

    @Test
    void anOriginIgnoresUnreadableInfluence() throws Exception {
        Headers h = validHeaders();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        new InboundFilter(null, false, true, "payment", null, null, null, null).doFilter(
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(200, response.getStatus());
        assertEquals(List.of(), seen.influence, "an origin carries none, so none is dropped");
    }

    @Test
    void aServiceWithAStampKeyButNoVerifierNeverAttests() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        nonEnforcingFilter(null).doFilter(
                paymentRequest(validHeaders(), TO_PAYMENT), response, new MockFilterChain(new Answering()));

        assertEquals("paid", response.getContentAsString());
        assertNull(response.getHeader(PaztportHeaders.RESPONSE), "it cannot know the chain is good");
    }

    @Test
    void verifyingRequestsNeedsAVerifierAModeAndAPublisher() {
        assertThrows(IllegalArgumentException.class,
                () -> new InboundFilter(null, true, false, "payment", new ModeHolder(VerificationMode.ENFORCE),
                        events, null, null));
    }

    @Test
    void aPeerWhoseCertificateNamesNoServiceIsShownQuoted() {
        String line = InboundFilter.traceLine("rid-1",
                new VerifyResult(ReasonCode.PEER_MISMATCH, "", "10.0.0.9"),
                "payment", new Peer("", "10.0.0.9"), List.of());

        assertEquals("PAZTPORT_TRACE request rid=rid-1 reason=PEER_MISMATCH receiver=payment ✗ peer=\"\" (mTLS) "
                + "classes=-", line);
    }

    @Test
    void anAuditFailureIsServedButNotAttested() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(paymentVerifier(), VerificationMode.AUDIT).doFilter(
                paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), response,
                new MockFilterChain(new Answering()));

        assertEquals("paid", response.getContentAsString(), "audit passes the request through");
        assertNull(response.getHeader(PaztportHeaders.RESPONSE), "but vouches for nothing it answered");
    }

    @Test
    void aRefusalIsNotAttested() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), response,
                new MockFilterChain(new Answering()));

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(PaztportHeaders.RESPONSE));
    }

    @Test
    void withoutAnInboundChainThereIsNothingToAttestOnto() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        nonEnforcingFilter(paymentVerifier()).doFilter(
                paymentRequest(new Headers(null, null, null), TO_PAYMENT), response,
                new MockFilterChain(new Answering()));

        assertEquals("paid", response.getContentAsString());
        assertNull(response.getHeader(PaztportHeaders.RESPONSE));
    }

    @Test
    void theHandlerRunsInsideAScopeThatClosesAfterIt() throws Exception {
        Seen seen = new Seen();

        filter(VerificationMode.ENFORCE, null).doFilter(paymentRequest(validHeaders(), TO_PAYMENT),
                new MockHttpServletResponse(), new MockFilterChain(seen));

        assertTrue(seen.scoped, "what the handler's calls learn is recorded");
        assertTrue(!PaztportContext.isOpen(), "and dropped when the request ends");
    }

    @Test
    void aRidTheResponseBindingCannotCarryIsServedUnattestedWithAWarning() throws Exception {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger filterLog = (Logger) LoggerFactory.getLogger(InboundFilter.class);
        warnings.start();
        filterLog.addAppender(warnings);
        filterLog.setLevel(Level.WARN);
        filterLog.setAdditive(false);
        try {
            MockHttpServletResponse response = new MockHttpServletResponse();

            // Signed and verified, but a newline cannot be a response's call id.
            attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                    paymentRequest(headers("r\nx", "/pay", List.of()), TO_PAYMENT), response,
                    new MockFilterChain(new Answering()));

            assertEquals("paid", response.getContentAsString());
            assertNull(response.getHeader(PaztportHeaders.RESPONSE));
            assertEquals(1, warnings.list.size());
            String warning = warnings.list.get(0).getFormattedMessage();
            assertTrue(warning.startsWith("response left unattested: rid=r\\u000ax "), warning);
        } finally {
            filterLog.detachAppender(warnings);
            filterLog.setLevel(null);
            filterLog.setAdditive(true);
        }
    }

    @Test
    void aScopeLeakedOnThisThreadIsEndedWithAWarningAndRequestsAreStillServed() throws Exception {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger filterLog = (Logger) LoggerFactory.getLogger(InboundFilter.class);
        warnings.start();
        filterLog.addAppender(warnings);
        filterLog.setLevel(Level.WARN);
        filterLog.setAdditive(false);
        try {
            // Code outside the filter opened a scope on this pooled thread, recorded something, and never closed it.
            PaztportContext.open();
            PaztportContext.addInfluence(WEB);

            Seen first = new Seen();
            MockHttpServletResponse firstResponse = new MockHttpServletResponse();
            filter(VerificationMode.ENFORCE, null).doFilter(paymentRequest(validHeaders(), TO_PAYMENT),
                    firstResponse, new MockFilterChain(first));

            assertEquals(200, firstResponse.getStatus());
            assertTrue(first.reached && first.scoped);
            assertEquals(List.of(), first.influence, "nothing the leaked scope held reaches the request");
            assertTrue(!PaztportContext.isOpen());
            assertEquals(1, warnings.list.size());
            String warning = warnings.list.get(0).getFormattedMessage();
            assertTrue(warning.startsWith("a paztport context scope was leaked on thread "), warning);

            Seen second = new Seen();
            MockHttpServletResponse secondResponse = new MockHttpServletResponse();
            filter(VerificationMode.ENFORCE, null).doFilter(
                    paymentRequest(headers("rid-2", "/pay", List.of()), TO_PAYMENT), secondResponse,
                    new MockFilterChain(second));

            assertEquals(200, secondResponse.getStatus());
            assertTrue(second.reached);
            assertEquals(1, warnings.list.size(), "the thread is clean again");
        } finally {
            filterLog.detachAppender(warnings);
            filterLog.setLevel(null);
            filterLog.setAdditive(true);
        }
    }
}
