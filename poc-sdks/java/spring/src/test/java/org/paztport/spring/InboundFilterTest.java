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
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
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
 * that holds an attested answer whole, and the listed paths left unfiltered. What the receiver decides is
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
    /** Payment acting on influence, as a service whose handlers read what they are handed does. */
    private static final ExtensionSettings INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);

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
        // Every scope a test opens is closed by it or by the filter; one left open would follow this thread.
        assertFalse(RequestContext.isOpen(), "a test left a request scope open on this thread");
    }

    /** Payment's verifier, acting on influence. */
    private Verifier paymentVerifier() {
        return paymentVerifier(INFLUENCE);
    }

    private Verifier paymentVerifier(ExtensionSettings settings) {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> NOW, 5000, 5000, settings));
    }

    private static final List<String> CONFIGURED = List.of("/admin", "/debug", "/actuator");

    private InboundFilter filter(VerificationMode mode, ReceivedRequestListener listener) {
        return filter(mode, listener, List.of());
    }

    private InboundFilter filter(VerificationMode mode, ReceivedRequestListener listener, List<String> unverified) {
        return new InboundFilter(paymentVerifier(), true, false, "payment", new ModeHolder(mode), events, listener,
                null, null, ObservationRegistry.NOOP, unverified, INFLUENCE);
    }

    /**
     * A hop that neither verifies requests nor holds a verifier or a stamp key, acting on what {@code settings} say,
     * which it holds only here.
     */
    private static InboundFilter plainFilter(ExtensionSettings settings) {
        return new InboundFilter(null, false, false, "payment", null, null, null, null,
                null, ObservationRegistry.NOOP, List.of(), settings);
    }

    private Stamper paymentStamper() {
        return new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW);
    }

    /** Payment verifying requests and holding a stamp key, so it attests what it answers to a verified chain. */
    private InboundFilter attestingFilter(Verifier verifier, VerificationMode mode) {
        return new InboundFilter(verifier, true, false, "payment", new ModeHolder(mode), events, null,
                paymentStamper(), null, ObservationRegistry.NOOP, List.of(), verifier.extensions());
    }

    private record Headers(String chain, String proof, String blocks) {
    }

    /** A chain gateway to orders to payment; orders acts on influence and signs {@code influence} in its block. */
    private Headers headers(String rid, String target, List<InfluenceEntry> influence) {
        return headers(rid, target, Influence.block(influence, List.of()));
    }

    /** As above, with orders' own block {@code own}; gateway signs the empty block. */
    private Headers headers(String rid, String target, Block own) {
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), Block.EMPTY,
                        policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", target, TO_PAYMENT), own,
                        policy.bundles().get("orders"));
        return new Headers(HttpWire.encodeChain(ord.chain()), HttpWire.encodeProof(ord.proof()),
                HttpWire.encodeBlocks(List.of(Block.EMPTY, own)));
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
        if (h.blocks() != null) {
            request.addHeader(PaztportHeaders.EXTENSIONS, h.blocks());
        }
        request.setContent(body);
        return request;
    }

    /** The entries the open scope's service was handed under influence, as the rules read them. */
    private static List<InfluenceEntry> handed() {
        HandOver handedOn = RequestContext.handedOn();
        return handedOn == null ? List.of() : Influence.readRequest(handedOn.under(Influence.NAME)).entries();
    }

    /** A handler that records what the context held while the request was served. */
    private static final class Seen extends HttpServlet {
        List<Stamp> chain;
        List<InfluenceEntry> handed;
        Boolean verified;
        List<InfluenceEntry> added;
        boolean reached;
        boolean scoped;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) {
            reached = true;
            scoped = RequestContext.isOpen();
            chain = RequestContext.inboundChain();
            handed = handed();
            verified = RequestContext.handedOn() == null ? null : RequestContext.handedOn().verified();
            added = RequestContext.added();
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
        assertEquals(List.of(MINE, WEB), seen.handed, "orders' entries, handed on");
        assertEquals(true, seen.verified);
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

    // A request served without verifying is handed what its blocks hold, marked not verified (spec verification.md,
    // What a request served without verifying is handed).
    @Test
    void nonVerifyingFilterPopulatesContextFromTheHeadersAndProceeds() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        plainFilter(INFLUENCE).doFilter(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(200, response.getStatus());
        assertEquals(2, seen.chain.size());
        assertEquals("rid-1", seen.chain.get(0).rid());
        assertEquals(List.of(WEB), seen.handed);
        assertEquals(false, seen.verified);
        assertTrue(traceLines().isEmpty(), "nothing was verified");
    }

    // Blocks that do not decode cannot be matched to the stamps, so check 9a fails and the request is not served,
    // even at a service that acts on no extension (spec verification.md, "A service never serves a request whose
    // blocks fail check 9a").
    @Test
    void nonVerifyingFilterAnswersBlocksThatDoNotDecodeWith400() throws Exception {
        Headers h = validHeaders();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Seen seen = new Seen();

        plainFilter(ExtensionSettings.NONE).doFilter(
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), response,
                new MockFilterChain(seen));

        assertEquals(400, response.getStatus());
        assertEquals("{\"reason\":\"EXTENSION_MISMATCH\"}", response.getContentAsString());
        assertTrue(!seen.reached, "blocks that cannot be carried must not be dropped");
    }

    // An item under influence that does not read as an entry: only a service that acts on influence reads it, and it
    // refuses it in every mode, verified or not; one that acts on nothing reads no item and serves the request (spec
    // influence.md, Entries and What the rules read).
    @Test
    void anItemThatDoesNotReadIsRefusedOnlyWhereTheServiceActsOnInfluence() throws Exception {
        Block unreadable = Block.of(Map.of(Influence.NAME, List.of("{\"cls\":\"no-such-class\"}")), List.of());
        Map<String, InboundFilter> filters = Map.of(
                "verifying", filter(VerificationMode.ENFORCE, null),
                "served unverified", plainFilter(INFLUENCE));
        int rid = 0;
        for (Map.Entry<String, InboundFilter> acting : filters.entrySet()) {
            MockHttpServletResponse refused = new MockHttpServletResponse();
            Seen seen = new Seen();

            acting.getValue().doFilter(paymentRequest(headers("rid-u" + rid++, "/pay", unreadable), TO_PAYMENT),
                    refused, new MockFilterChain(seen));

            assertEquals(400, refused.getStatus(), acting.getKey());
            assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", refused.getContentAsString(), acting.getKey());
            assertFalse(seen.reached, acting.getKey());
        }

        MockHttpServletResponse served = new MockHttpServletResponse();
        Seen seen = new Seen();
        plainFilter(ExtensionSettings.NONE).doFilter(paymentRequest(headers("rid-u9", "/pay", unreadable),
                TO_PAYMENT), served, new MockFilterChain(seen));

        assertEquals(200, served.getStatus());
        assertTrue(seen.reached);
        assertEquals(List.of(), seen.handed, "a service acting on nothing is handed nothing under influence");
    }

    @Test
    void configuredPathsBypassVerification() throws Exception {
        // A path listed in paztport.unverified-paths needs no headers and reaches its handler.
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/mode");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.ENFORCE, null, CONFIGURED).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest(), "an unverified path must reach its handler");
    }

    @Test
    void unverifiedPathsAreNoneByDefault() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(VerificationMode.ENFORCE, null).doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("{\"reason\":\"CHAIN_MISSING\"}", response.getContentAsString());
        assertNull(chain.getRequest(), "refused before the handler");
        assertFalse(InboundFilter.unverified("/actuator/health", List.of()));
    }

    @Test
    void configuredPrefixesAreNotVerified() {
        for (String path : List.of("/admin", "/admin/", "/admin/mode", "/debug", "/debug/last-request", "/actuator",
                "/actuator/health")) {
            assertTrue(InboundFilter.unverified(path, CONFIGURED), path);
        }
    }

    // Matched by segment, not by text: a data-path name that only begins like a listed one is verified.
    @Test
    void namesThatOnlyBeginLikeAnUnverifiedPathAreVerified() {
        for (String path : List.of("/administration", "/admins/1", "/debugger", "/debug-report", "/actuators",
                "/actuatorhealth", "/admin;x/mode", "/x/admin", "/", "")) {
            assertFalse(InboundFilter.unverified(path, CONFIGURED), path);
        }
    }

    // Whatever resolves a dot segment could take it off a listed path, so a path holding one is verified.
    @Test
    void unverifiedPathsWithADotSegmentAreVerified() {
        for (String path : List.of("/admin/../pay", "/admin/%2e%2e/pay", "/admin/%2E%2e/pay", "/admin/.%2E/pay",
                "/admin/..;/pay", "/admin/..;x=1/pay", "/actuator/../pay", "/debug/./../pay", "/admin/.", "/admin/..",
                "/admin/%2e", "/admin/.;x/mode")) {
            assertFalse(InboundFilter.unverified(path, CONFIGURED), path);
        }
    }

    // Something downstream might read an encoded slash or a backslash as a separator, so a path with one is verified.
    @Test
    void unverifiedPathsWithAnEncodedOrBackslashSeparatorAreVerified() {
        for (String path : List.of("/admin/..%2fpay", "/admin/..%2Fpay", "/admin%2f..%2fpay", "/admin/x%2fy",
                "/admin/..%5cpay", "/admin/..%5Cpay", "/admin/..\\pay", "/admin\\mode", "/actuator/health%2F",
                "/debug/%5c")) {
            assertFalse(InboundFilter.unverified(path, CONFIGURED), path);
        }
    }

    // Only the plain spelling is a listed path: an encoded, doubled or extended first segment is verified.
    @Test
    void otherSpellingsOfAnUnverifiedPathAreVerified() {
        for (String path : List.of("/%61dmin", "/%61dmin/mode", "//admin", "//admin/mode", "/admin.", "/admin;x",
                "/ADMIN/mode")) {
            assertFalse(InboundFilter.unverified(path, CONFIGURED), path);
        }
        // A segment that only holds dots among other text is a name, not a dot segment.
        assertTrue(InboundFilter.unverified("/admin/.well-known", CONFIGURED));
        assertTrue(InboundFilter.unverified("/actuator/health..json", CONFIGURED));
    }

    @Test
    void aDataPathThatBeginsLikeAnUnverifiedPathIsRefusedWithoutAChain() throws Exception {
        for (String path : List.of("/administration", "/admin/../pay")) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
            request.setContent(new byte[0]);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter(VerificationMode.ENFORCE, null, CONFIGURED).doFilter(request, response, chain);

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
        assertNull(RequestContext.handedOn());
        assertTrue(RequestContext.added().isEmpty());
    }

    /** Two endpoints: one dirties the context, the other reports what it found. */
    @RestController
    static final class ReuseController {
        List<Stamp> chain;
        List<InfluenceEntry> handed;
        List<InfluenceEntry> added;
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
            handed = handed();
            added = RequestContext.added();
            labels = RequestContext.labels();
            return "ok";
        }
    }

    @Test
    void threadReuseStartsClean() throws Exception {
        ReuseController controller = new ReuseController();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .addFilters(plainFilter(INFLUENCE))
                .build();
        Headers first = headers("rid-1", "/pay", List.of(MINE));
        Headers second = headers("rid-2", "/pay", List.of());

        // MockMvc serves both on this test thread, as a pooled server thread would serve two requests.
        mvc.perform(post("/dirty").header(PaztportHeaders.CHAIN, first.chain())
                        .header(PaztportHeaders.EXTENSIONS, first.blocks()).content(TO_PAYMENT))
                .andExpect(status().isOk());
        mvc.perform(post("/look").header(PaztportHeaders.CHAIN, second.chain())
                        .header(PaztportHeaders.EXTENSIONS, second.blocks()).content(TO_PAYMENT))
                .andExpect(status().isOk());

        assertEquals("rid-2", controller.chain.get(0).rid());
        assertEquals(2, controller.chain.size());
        assertEquals(List.of(), controller.handed);
        assertEquals(List.of(), controller.added);
        assertEquals(List.of(), controller.labels);
    }

    private static final class CollectingPublisher implements EventPublisher {
        final List<AttestationEvent> all = new ArrayList<>();

        @Override
        public void publish(AttestationEvent event) {
            all.add(event);
        }
    }

    // A refusal is for the caller: the body is the reason alone. The suspect, with whatever inst it
    // signed, goes to the event; the trace line, with no peer here, names no suspect.
    @Test
    void theRefusalBodyIsTheReasonAloneWhateverTheSuspectSigned() throws Exception {
        String inst = "ord\"1\\";
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .next(null, "orders", "b", Block.EMPTY, policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", inst, orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), Block.EMPTY,
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

    // Payment acts on influence, so the handler's label rides in the response's own block, which requires influence
    // of the caller and which the response stamp commits to; the binding covers the status and the body (spec
    // influence.md, Content labels; wire.md, HTTP responses).
    @Test
    void aVerifiedRequestsResponseIsAttestedOverWhatTheHandlerSent() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(paymentVerifier(), VerificationMode.ENFORCE).doFilter(
                paymentRequest(validHeaders(), TO_PAYMENT), response, new MockFilterChain(new Answering()));

        assertEquals(201, response.getStatus());
        assertEquals("paid", response.getContentAsString(), "the body still reaches the caller");
        JsonNode attestation = decodeAttestation(response);
        List<String> members = new ArrayList<>();
        attestation.fieldNames().forEachRemaining(members::add);
        assertEquals(List.of("block", "stamp"), members, "the response header is {block, stamp}");
        Block block = Block.parseAll("[" + JsonWriter.text(JsonFields.object(
                JsonReader.token(response.getHeader(PaztportHeaders.RESPONSE))).get("block")) + "]").get(0);
        List<ContentLabel> labels = block.itemsUnder(Influence.NAME).stream().map(ContentLabel::parse).toList();
        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        assertEquals(List.of(Influence.NAME), block.requires(), "a labelled answer requires influence of its caller");
        Stamp stamp = Chains.parse(
                new ObjectMapper().createArrayNode().add(attestation.get("stamp")).toString()).stamps().get(0);
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv(), "the response goes back to whoever called");
        assertEquals("rid-1", stamp.rid());
        assertEquals(block.commit(), stamp.ext());
        assertEquals(Bindings.response(HttpWire.resultHash(201, "paid".getBytes(StandardCharsets.UTF_8)), "rid-1"),
                stamp.bind());
    }

    @Test
    void verifyingRequestsNeedsAVerifierAModeAndAPublisher() {
        assertThrows(IllegalArgumentException.class,
                () -> new InboundFilter(null, true, false, "payment", new ModeHolder(VerificationMode.ENFORCE),
                        events, null, null, null, ObservationRegistry.NOOP, List.of(), INFLUENCE));
    }

    @Test
    void aMalformedUnverifiedPathIsRefusedByTheFilterItself() {
        for (String entry : new String[] {"", "/", "admin", "/admin/", "/a//b", "/admin;x", "/..", "/ad\\min"}) {
            IllegalStateException refusal = assertThrows(IllegalStateException.class,
                    () -> filter(VerificationMode.ENFORCE, null, List.of(entry)), entry);
            assertTrue(refusal.getMessage().contains("paztport.unverified-paths"), refusal.getMessage());
            assertTrue(refusal.getMessage().contains("\"" + entry + "\""), refusal.getMessage());
        }
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
        // Closed in the finally whatever happens: if the filter's leak handling regressed, a scope left open would
        // fail every later test with "already open" and bury this one's failure. Closing an ended scope does nothing.
        RequestContext.Scope firstLeak = null;
        RequestContext.Scope secondLeak = null;
        try {
            // Code outside the filter opened a scope on this pooled thread, recorded something, and never closed it.
            firstLeak = RequestContext.open();
            RequestContext.addInfluence(WEB);

            Seen first = new Seen();
            MockHttpServletResponse firstResponse = new MockHttpServletResponse();
            List<Object> listened = new ArrayList<>();
            filter(VerificationMode.ENFORCE, (chain, proof, blocks, method, target, body) -> {
                listened.add(warnings.list.size());
                listened.add(RequestContext.isOpen());
                listened.add(RequestContext.inboundChain().get(0).rid());
                listened.add(RequestContext.added());
            }).doFilter(paymentRequest(validHeaders(), TO_PAYMENT), firstResponse, new MockFilterChain(first));

            assertEquals(List.of(1, true, "rid-1", List.of()), listened,
                    "the leak was ended first, and the listener ran in the request's own scope");
            assertEquals(200, firstResponse.getStatus());
            assertTrue(first.reached && first.scoped);
            assertEquals(List.of(), first.added, "nothing the leaked scope held reaches the request");
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
            secondLeak = RequestContext.open();
            RequestContext.addInfluence(WEB);
            MockHttpServletRequest unstamped = new MockHttpServletRequest("POST", "/pay");
            unstamped.setContent(TO_PAYMENT);
            MockHttpServletResponse refused = new MockHttpServletResponse();
            filter(VerificationMode.ENFORCE, null).doFilter(unstamped, refused, new MockFilterChain());

            assertEquals(403, refused.getStatus());
            assertTrue(!RequestContext.isOpen(), "the thread is clean after a refusal too");
            assertEquals(List.of(), RequestContext.added());
            assertEquals(2, warnings.list.size());
        } finally {
            if (secondLeak != null) {
                secondLeak.close();
            }
            if (firstLeak != null) {
                firstLeak.close();
            }
            filterLog.detachAppender(warnings);
            filterLog.setLevel(null);
            filterLog.setAdditive(true);
        }
    }
}
