// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.ContextAccess;
import org.paztport.http.ModeHolder;
import org.paztport.http.ReceivedRequestListener;
import org.paztport.http.RequestContext;
import org.paztport.http.VerificationMode;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The servlet half of the inbound path: the body cached and passed on, the raw target the receiver is handed, the
 * receiver's refusals written as JSON before any handler, the scope the handler runs in and what it holds, the wrapper
 * that holds an attested answer whole, and the control plane left unfiltered. What the receiver decides is
 * {@code HttpReceiverTest}'s, in {@code paztport-http}; the cases here that overlap it check that the servlet carries
 * the decision through.
 */
class InboundFilterTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders")), 4, NOT_AFTER,
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
        ContextAccess.reset();
    }

    private Verifier paymentVerifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> NOW, 5000, 5000));
    }

    private InboundFilter filter(VerificationMode mode, ReceivedRequestListener listener) {
        return new InboundFilter(paymentVerifier(), true, false, "payment", new ModeHolder(mode), events, listener,
                null, null, ObservationRegistry.NOOP);
    }

    /** A hop that neither verifies requests nor holds a verifier or a stamp key. */
    private static InboundFilter plainFilter() {
        return new InboundFilter(null, false, false, "payment", null, null, null, null,
                null, ObservationRegistry.NOOP);
    }

    private Stamper paymentStamper() {
        return new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW);
    }

    /** Payment verifying requests and holding a stamp key, so it attests what it answers to a verified chain. */
    private InboundFilter attestingFilter(Verifier verifier, VerificationMode mode) {
        return new InboundFilter(verifier, true, false, "payment", new ModeHolder(mode), events, null,
                paymentStamper(), null, ObservationRegistry.NOOP);
    }

    private record Headers(String chain, String proof, String influence) {
    }

    private Headers headers(String rid, String target, List<InfluenceEntry> influence) {
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", target, TO_PAYMENT), influence,
                        policy.bundles().get("orders"));
        return new Headers(HttpWire.encodeChain(ord.chain()), HttpWire.encodeProof(ord.proof()),
                HttpWire.encodeInfluence(influence));
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
        List<Stamp> chain;
        List<InfluenceEntry> influence;
        boolean reached;
        boolean scoped;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) {
            reached = true;
            scoped = RequestContext.isOpen();
            chain = RequestContext.inboundChain();
            influence = RequestContext.influence();
        }
    }

    /** A handler that labels what it answers, as a service serving alice's data would. */
    private static final class Answering extends HttpServlet {
        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
            RequestContext.label(InfluenceClass.PRIVATE, "alice");
            res.setStatus(201);
            res.getOutputStream().write("paid".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static JsonNode decodeAttestation(MockHttpServletResponse response) throws IOException {
        return new ObjectMapper().readTree(HttpWire.decodeChain(response.getHeader(PaztportHeaders.RESPONSE)));
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
    void wholeControlPlaneSegmentsAreLeftUnverified() {
        for (String path : List.of("/admin", "/admin/", "/admin/mode", "/debug", "/debug/last-request", "/actuator",
                "/actuator/health")) {
            assertTrue(InboundFilter.controlPlane(path), path);
        }
    }

    // Matched by segment, not by text: a data-path name that only begins like a control-plane one is verified.
    @Test
    void namesThatOnlyBeginLikeTheControlPlaneAreVerified() {
        for (String path : List.of("/administration", "/admins/1", "/debugger", "/debug-report", "/actuators",
                "/actuatorhealth", "/admin;x/mode", "/x/admin", "/", "")) {
            assertFalse(InboundFilter.controlPlane(path), path);
        }
    }

    // Whatever resolves a dot segment could take it off the control plane, so a path holding one is verified.
    @Test
    void controlPlanePathsWithADotSegmentAreVerified() {
        for (String path : List.of("/admin/../pay", "/admin/%2e%2e/pay", "/admin/%2E%2e/pay", "/admin/.%2E/pay",
                "/admin/..;/pay", "/admin/..;x=1/pay", "/actuator/../pay", "/debug/./../pay", "/admin/.", "/admin/..",
                "/admin/%2e", "/admin/.;x/mode")) {
            assertFalse(InboundFilter.controlPlane(path), path);
        }
    }

    // Something downstream might read an encoded slash or a backslash as a separator, so a path with one is verified.
    @Test
    void controlPlanePathsWithAnEncodedOrBackslashSeparatorAreVerified() {
        for (String path : List.of("/admin/..%2fpay", "/admin/..%2Fpay", "/admin%2f..%2fpay", "/admin/x%2fy",
                "/admin/..%5cpay", "/admin/..%5Cpay", "/admin/..\\pay", "/admin\\mode", "/actuator/health%2F",
                "/debug/%5c")) {
            assertFalse(InboundFilter.controlPlane(path), path);
        }
    }

    // Only the plain spelling is the control plane: an encoded, doubled or extended first segment is verified.
    @Test
    void otherSpellingsOfTheControlPlaneAreVerified() {
        for (String path : List.of("/%61dmin", "/%61dmin/mode", "//admin", "//admin/mode", "/admin.", "/admin;x",
                "/ADMIN/mode")) {
            assertFalse(InboundFilter.controlPlane(path), path);
        }
        // A segment that only holds dots among other text is a name, not a dot segment.
        assertTrue(InboundFilter.controlPlane("/admin/.well-known"));
        assertTrue(InboundFilter.controlPlane("/actuator/health..json"));
    }

    @Test
    void aDataPathThatBeginsLikeTheControlPlaneIsRefusedWithoutAChain() throws Exception {
        for (String path : List.of("/administration", "/admin/../pay")) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
            request.setContent(new byte[0]);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter(VerificationMode.ENFORCE, null).doFilter(request, response, chain);

            assertEquals(403, response.getStatus(), path);
            assertEquals("{\"reason\":\"CHAIN_MISSING\"}", response.getContentAsString(), path);
            assertNull(chain.getRequest(), path + ": refused before the handler");
        }
    }

    @Test
    void contextIsClearedAfterTheRequest() throws Exception {
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), new MockHttpServletResponse(),
                new MockFilterChain());

        assertNull(RequestContext.inboundChain());
        assertTrue(RequestContext.influence().isEmpty());
    }

    /** Two endpoints: one dirties the context, the other reports what it found. */
    @RestController
    static final class ReuseController {
        List<Stamp> chain;
        List<InfluenceEntry> influence;
        List<ContentLabel> labels;

        @PostMapping("/dirty")
        String dirty() {
            RequestContext.addInfluence(WEB);
            RequestContext.label(InfluenceClass.PRIVATE, "alice");
            return "ok";
        }

        @PostMapping("/look")
        String look() {
            chain = RequestContext.inboundChain();
            influence = RequestContext.influence();
            labels = RequestContext.labels();
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

    // A refusal is for the caller, who is usually the suspect: the body is the reason alone. The suspect, with
    // whatever inst it signed, goes to the event; the trace line, with no peer here, names no suspect.
    @Test
    void theRefusalBodyIsTheReasonAloneWhateverTheSuspectSigned() throws Exception {
        String inst = "ord\"1\\";
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .next(null, "orders", "b", List.of(), policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", inst, orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), List.of(),
                        policy.bundles().get("orders"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        // No proof, so the route is unproven and the last signer, with its chosen inst, is the suspect.
        filter(VerificationMode.ENFORCE, null).doFilter(
                paymentRequest(new Headers(HttpWire.encodeChain(ord.chain()), null, null), TO_PAYMENT),
                response, new MockFilterChain());

        assertEquals(403, response.getStatus());
        assertEquals("{\"reason\":\"PATH_NOT_ALLOWED\"}", response.getContentAsString());
        assertEquals("application/json", response.getContentType());
        assertEquals(1, events.all.size());
        assertEquals("orders", events.all.get(0).suspectSvc());
        assertEquals(inst, events.all.get(0).suspectInst());
        assertEquals(1, traceLines().size());
        assertTrue(traceLines().get(0).contains(" reason=PATH_NOT_ALLOWED receiver=payment ✗ peer=none "),
                traceLines().get(0));
    }

    @Test
    void aVerifiedRequestsResponseIsAttestedOverWhatTheHandlerSent() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                paymentRequest(validHeaders(), TO_PAYMENT), response, new MockFilterChain(new Answering()));

        assertEquals(201, response.getStatus());
        assertEquals("paid", response.getContentAsString(), "the body still reaches the caller");
        JsonNode attestation = decodeAttestation(response);
        List<ContentLabel> labels = ContentLabel.parseAll(JsonWriter.text(
                JsonFields.object(JsonReader.token(response.getHeader(PaztportHeaders.RESPONSE))).get("labels")));
        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        Stamp stamp = Chains.parse(
                new ObjectMapper().createArrayNode().add(attestation.get("stamp")).toString()).stamps().get(0);
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv(), "the response goes back to whoever called");
        assertEquals("rid-1", stamp.rid());
        assertEquals(Bindings.response(HttpWire.resultHash(201, "paid".getBytes(StandardCharsets.UTF_8)), "rid-1",
                labels), stamp.bind());
    }

    @Test
    void verifyingRequestsNeedsAVerifierAModeAndAPublisher() {
        assertThrows(IllegalArgumentException.class,
                () -> new InboundFilter(null, true, false, "payment", new ModeHolder(VerificationMode.ENFORCE),
                        events, null, null, null, ObservationRegistry.NOOP));
    }

    @Test
    void theHandlerRunsInsideAScopeThatClosesAfterIt() throws Exception {
        Seen seen = new Seen();

        filter(VerificationMode.ENFORCE, null).doFilter(paymentRequest(validHeaders(), TO_PAYMENT),
                new MockHttpServletResponse(), new MockFilterChain(seen));

        assertTrue(seen.scoped, "what the handler's calls learn is recorded");
        assertTrue(!RequestContext.isOpen(), "and dropped when the request ends");
    }

    @Test
    void aScopeLeakedOnThisThreadIsEndedWithAWarningAndRequestsAreStillServed() throws Exception {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger filterLog = (Logger) LoggerFactory.getLogger(RequestContext.class);
        warnings.start();
        filterLog.addAppender(warnings);
        filterLog.setLevel(Level.WARN);
        filterLog.setAdditive(false);
        try {
            // Code outside the filter opened a scope on this pooled thread, recorded something, and never closed it.
            RequestContext.open();
            RequestContext.addInfluence(WEB);

            Seen first = new Seen();
            MockHttpServletResponse firstResponse = new MockHttpServletResponse();
            List<Object> listened = new ArrayList<>();
            filter(VerificationMode.ENFORCE, (chain, proof, influence, method, target, body) -> {
                listened.add(warnings.list.size());
                listened.add(RequestContext.isOpen());
                listened.add(RequestContext.inboundChain().get(0).rid());
                listened.add(RequestContext.influence());
            }).doFilter(paymentRequest(validHeaders(), TO_PAYMENT), firstResponse, new MockFilterChain(first));

            assertEquals(List.of(1, true, "rid-1", List.of()), listened,
                    "the leak was ended first, and the listener ran in the request's own scope");
            assertEquals(200, firstResponse.getStatus());
            assertTrue(first.reached && first.scoped);
            assertEquals(List.of(), first.influence, "nothing the leaked scope held reaches the request");
            assertTrue(!RequestContext.isOpen());
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

            // A request that is refused ends a leaked scope as well, so no stale scope outlives any request.
            RequestContext.open();
            RequestContext.addInfluence(WEB);
            MockHttpServletRequest unstamped = new MockHttpServletRequest("POST", "/pay");
            unstamped.setContent(TO_PAYMENT);
            MockHttpServletResponse refused = new MockHttpServletResponse();
            filter(VerificationMode.ENFORCE, null).doFilter(unstamped, refused, new MockFilterChain());

            assertEquals(403, refused.getStatus());
            assertTrue(!RequestContext.isOpen(), "the thread is clean after a refusal too");
            assertEquals(List.of(), RequestContext.influence());
            assertEquals(2, warnings.list.size());
        } finally {
            filterLog.detachAppender(warnings);
            filterLog.setLevel(null);
            filterLog.setAdditive(true);
        }
    }
}
