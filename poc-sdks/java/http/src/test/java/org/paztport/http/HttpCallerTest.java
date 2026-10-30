// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.RecordedStamp;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.slf4j.LoggerFactory;

class HttpCallerTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private static final URI ORDERS = URI.create("http://orders:8080/orders");
    private static final byte[] NO_BODY = new byte[0];

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders"),
                    List.of("gateway", "search")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

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
        RequestContext.reset();
    }

    private List<String> traceLines() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    /** What gateway uses to check the responses it gets: it trusts gateway and orders, and gateway is the origin. */
    private VerifierV3 gatewayVerifier() {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", orders.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), policy.signedRoot().notAfter(),
                Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> 2500L, 5000, 5000));
    }

    private StamperV3 gatewayStamper() {
        return new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L);
    }

    private StamperV3 ordersStamper() {
        return new StamperV3("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 2000L);
    }

    /** Gateway's caller, which holds its proofs but checks no response. */
    private HttpCaller gatewayCaller() {
        return HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway")).build();
    }

    /** Gateway's caller, which checks every response. */
    private HttpCaller verifyingCaller() {
        return HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway"))
                .verifier(gatewayVerifier()).build();
    }

    /** Orders' {@code X-Path-Response} over {@code attested}, as its receiver would send it, to the call sent. */
    private String attestation(HttpCaller.Outbound sent, String attested, List<ContentLabel> labels) {
        List<StampV3> inbound = chainOf(sent.headers());
        String hash = HttpV3.resultHash(200, utf8(attested));
        StampV3 stamp = ordersStamper().respond(inbound, hash, inbound.get(0).rid(), labels);
        return HttpV3.encodeResponse(stamp, labels);
    }

    private static List<StampV3> chainOf(Map<String, String> headers) {
        List<RecordedStamp> stamps = Chains.parse(HttpV3.decodeChain(headers.get(PaztportHeaders.CHAIN)), false)
                .stamps();
        return stamps.stream().map(StampV3.class::cast).toList();
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // --- Stamping ---

    @Test
    void stampsForTheUriHostAndAttachesTheProof() {
        HttpCaller.Outbound sent = gatewayCaller().stampFromContext("POST", ORDERS, utf8("{}"));

        List<StampV3> chain = chainOf(sent.headers());
        assertEquals(1, chain.size());
        assertEquals("gateway", chain.get(0).svc());
        assertEquals("orders", chain.get(0).rcv());
        assertEquals("", chain.get(0).infl());
        assertEquals(sent.sent().chain(), chain, "the header carries the chain that was stamped");
        assertNotNull(sent.headers().get(PaztportHeaders.PROOF), "proof for gateway/orders must be attached");
    }

    @Test
    void appendsToTheInboundChainCommittingTheContextInfluence() {
        StamperV3.Stamped received = gatewayStamper().next(null, "orders", "b", List.of(),
                policy.bundles().get("gateway"));
        HttpCaller ordersCaller = HttpCaller.builder("orders", ordersStamper())
                .bundle(policy.bundles().get("orders")).build();
        HttpCaller.Outbound sent;
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(received.chain());
            RequestContext.addInfluence(MINE, WEB);

            sent = ordersCaller.stampFromContext("POST", URI.create("http://payment:8080/pay"), utf8("{\"amount\":1}"));
        }

        List<StampV3> chain = chainOf(sent.headers());
        assertEquals(2, chain.size());
        StampV3 last = chain.get(1);
        assertEquals("orders", last.svc());
        assertEquals("payment", last.rcv());
        assertEquals(Influence.commit(List.of(MINE, WEB)), last.infl());
        assertEquals(RequestBinding.compute("POST", "/pay", utf8("{\"amount\":1}")), last.bind());
        assertEquals(List.of(MINE, WEB),
                Influence.parse(HttpV3.decodeInfluence(sent.headers().get(PaztportHeaders.INFLUENCE))));
        assertNotNull(sent.headers().get(PaztportHeaders.PROOF));
    }

    // The function is the protocol: it stamps after what it is given, and the thread's context does not enter it.
    @Test
    void theFunctionStampsAfterWhatItIsGivenNotTheContext() {
        StamperV3.Stamped received = gatewayStamper().next(null, "orders", "b", List.of(),
                policy.bundles().get("gateway"));
        HttpCaller ordersCaller = HttpCaller.builder("orders", ordersStamper())
                .bundle(policy.bundles().get("orders")).build();
        HttpCaller.Outbound sent;
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.addInfluence(WEB);

            sent = ordersCaller.stamp("POST", URI.create("http://payment:8080/pay"), utf8("{}"), received.chain(),
                    List.of(MINE));
        }

        StampV3 last = chainOf(sent.headers()).get(1);
        assertEquals(Influence.commit(List.of(MINE)), last.infl());
        assertEquals(List.of(MINE),
                Influence.parse(HttpV3.decodeInfluence(sent.headers().get(PaztportHeaders.INFLUENCE))));
    }

    @Test
    void theHeadersAreTheChainThenTheProofThenTheInfluence() {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.addInfluence(WEB);
            assertEquals(List.of(PaztportHeaders.CHAIN, PaztportHeaders.PROOF, PaztportHeaders.INFLUENCE),
                    List.copyOf(gatewayCaller().stampFromContext("GET", ORDERS, NO_BODY).headers().keySet()));
        }
    }

    @Test
    void noInfluenceSendsNoInfluenceHeader() {
        HttpCaller.Outbound sent = gatewayCaller().stampFromContext("POST", ORDERS, utf8("{}"));

        assertNull(sent.headers().get(PaztportHeaders.INFLUENCE));
        assertEquals(Set.of(PaztportHeaders.CHAIN, PaztportHeaders.PROOF), sent.headers().keySet());
    }

    @Test
    void omitsTheProofHeaderWhenNoneIsHeldForTheRoute() {
        // gateway -> payment is not a route gateway holds a proof for.
        HttpCaller.Outbound sent = gatewayCaller().stampFromContext("POST", URI.create("http://payment:8080/pay"),
                utf8("{}"));

        assertNull(sent.headers().get(PaztportHeaders.PROOF));
    }

    @Test
    void bindsTheRawPathAndQueryAsSent() {
        HttpCaller.Outbound sent = gatewayCaller().stampFromContext("GET",
                URI.create("http://search:8080/search?q=caf%C3%A9%20x"), NO_BODY);

        StampV3 stamp = chainOf(sent.headers()).get(0);
        assertEquals("search", stamp.rcv());
        assertEquals(RequestBinding.compute("GET", "/search?q=caf%C3%A9%20x", NO_BODY), stamp.bind());
    }

    // --- Naming the receiver ---

    @Test
    void aMappedHostIsStampedForItsPolicyName() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway"))
                .receivers(Map.of("orders-internal", "orders")).build();

        HttpCaller.Outbound sent = caller.stampFromContext("GET", URI.create("https://orders-internal/x"), NO_BODY);

        assertEquals("orders", sent.sent().chain().get(0).rcv());
        assertEquals("orders", sent.receiver());
    }

    @Test
    void withNoMappingTheHostIsTheName() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper()).build();

        HttpCaller.Outbound sent = caller.stampFromContext("GET", URI.create("https://orders-internal/x"), NO_BODY);

        assertEquals("orders-internal", sent.sent().chain().get(0).rcv());
    }

    @Test
    void aMappedHostIsMatchedIgnoringCaseAndAHostNotListedIsItsOwnName() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper())
                .receivers(Map.of("Orders-Internal", "orders")).build();

        assertEquals("orders", caller.receiver(URI.create("https://ORDERS-internal:8443/x")));
        assertEquals("orders", caller.receiver(URI.create("https://orders-internal/x")));
        assertEquals("Search", caller.receiver(URI.create("https://Search/x")), "an unlisted host, as written");
        assertNull(caller.receiver(URI.create("file:/x")), "no host, no name, as before");
    }

    // The policy name is the response's target too: the nonce key, the service that must attest, and the src.
    @Test
    void aMappedReceiverIsTheResponsesTarget() {
        ContentLabel web = ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null);
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway"))
                .verifier(gatewayVerifier()).receivers(Map.of("orders-internal", "orders")).build();
        HttpCaller.Outbound sent = caller.stampFromContext("GET", URI.create("https://orders-internal/orders"),
                NO_BODY);

        HttpCaller.Received received = caller.check(sent, 200, attestation(sent, "hello", List.of(web)),
                utf8("hello"));

        assertEquals(ReasonCode.OK, received.check().result().reason());
        assertEquals(List.of(web.toEntry("http:orders", HttpV3.resultHash(200, utf8("hello")))),
                received.influence());
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓ labels=third-party"),
                traceLines());
    }

    // Nothing but case is normalised: the README's keys for these hosts rest on it.
    @Test
    void aHostIsMatchedAsTheUriGivesIt() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper())
                .receivers(Map.of("[::1]", "orders", "::2", "payment", "search", "search")).build();

        assertEquals("orders", caller.receiver(URI.create("http://[::1]:8080/x")), "an IPv6 host keeps its brackets");
        assertEquals("[::2]", caller.receiver(URI.create("http://[::2]:8080/x")), "so a key without them misses");
        assertEquals("search.", caller.receiver(URI.create("http://search.:8080/x")), "a trailing dot is kept");
    }

    @Test
    void aBlankOrTwiceListedMappingIsRefused() {
        HttpCaller.Builder builder = HttpCaller.builder("gateway", gatewayStamper());

        assertThrows(IllegalArgumentException.class, () -> builder.receivers(Map.of("orders-internal", " ")));
        assertThrows(IllegalArgumentException.class, () -> builder.receivers(Map.of("", "orders")));
        Map<String, String> twice = new TreeMap<>(Map.of("orders-internal", "orders", "ORDERS-INTERNAL", "payment"));
        assertThrows(IllegalArgumentException.class, () -> builder.receivers(twice));
    }

    @Test
    void aNullMappingIsRefusedByName() {
        HttpCaller.Builder builder = HttpCaller.builder("gateway", gatewayStamper());

        NullPointerException e = assertThrows(NullPointerException.class, () -> builder.receivers(null));
        assertEquals("receivers", e.getMessage());
    }

    // --- Responses ---

    @Test
    void aVerifiedResponseRecordsItsLabelsAsInfluence() {
        ContentLabel mine = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        ContentLabel web = ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null);
        HttpCaller caller = verifyingCaller();
        List<InfluenceEntry> recorded;
        HttpV3.ResponseCheck check;
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);
            check = caller.recordToContext(sent, 200, attestation(sent, "hello", List.of(mine, web)), utf8("hello"));
            recorded = RequestContext.influence();
        }

        String hash = HttpV3.resultHash(200, utf8("hello"));
        assertTrue(check.result().ok());
        assertEquals(List.of(mine.toEntry("http:orders", hash), web.toEntry("http:orders", hash)), recorded);
        assertEquals(List.of(), RequestContext.influence(), "closing the scope drops what it recorded");
        assertEquals(List.of("PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓"
                + " labels=private,third-party"), traceLines());
    }

    @Test
    void aVerifiedResponseWithNoLabelsAddsNothing() {
        HttpCaller caller = verifyingCaller();
        HttpCaller.Outbound sent = caller.stamp("GET", ORDERS, NO_BODY, null, List.of());

        HttpCaller.Received received = caller.check(sent, 200, attestation(sent, "hello", List.of()), utf8("hello"));

        assertEquals(ReasonCode.OK, received.check().result().reason());
        assertEquals(List.of(), received.influence(), "it vouched for its content and named no class for it");
    }

    @Test
    void aResponseThatFailsItsAttestationIsOneUntrustedEntry() {
        HttpCaller caller = verifyingCaller();
        List<InfluenceEntry> recorded;
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);
            caller.recordToContext(sent, 200,
                    attestation(sent, "hello", List.of(ContentLabel.fresh(InfluenceClass.PRIVATE, "alice"))),
                    utf8("hellx"));
            recorded = RequestContext.influence();
        }

        assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                HttpV3.resultHash(200, utf8("hellx")), null, null)),
                recorded, "labels the stamp does not commit to are not believed");
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=BINDING_MISMATCH receiver=gateway ✗ labels=-"),
                traceLines());
    }

    @Test
    void anUnattestedErrorIsOneUntrustedEntry() {
        HttpCaller caller = verifyingCaller();
        List<InfluenceEntry> recorded;
        try (RequestContext.Scope scope = RequestContext.open()) {
            caller.recordToContext(caller.stampFromContext("GET", ORDERS, NO_BODY), 500, null, utf8("boom"));
            recorded = RequestContext.influence();
        }

        assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                HttpV3.resultHash(500, utf8("boom")), null, null)),
                recorded);
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=CHAIN_MISSING receiver=gateway ✗ labels=-"),
                traceLines());
    }

    @Test
    void withoutAVerifierEveryResponseIsOneUntrustedEntry() {
        HttpCaller caller = gatewayCaller();
        List<InfluenceEntry> recorded;
        HttpV3.ResponseCheck check;
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);
            check = caller.recordToContext(sent, 200,
                    attestation(sent, "hello", List.of(ContentLabel.fresh(InfluenceClass.PUBLIC, null))),
                    utf8("hello"));
            recorded = RequestContext.influence();
        }

        assertNull(check, "nothing was checked");
        assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                HttpV3.resultHash(200, utf8("hello")), null, null)),
                recorded, "an attestation nobody checked counts for nothing");
        assertEquals(List.of("PAZTPORT_TRACE response rid=rid-1 from=orders reason=- receiver=gateway ✗ labels=-"),
                traceLines());
    }

    @Test
    void outsideAScopeNothingIsRecordedOrCarried() {
        // A scheduled job or a startup runner: no request, so no scope, on a thread that is reused.
        AtomicInteger rids = new AtomicInteger();
        StamperV3 stamper = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true,
                () -> "rid-" + rids.incrementAndGet(), () -> 1000L);
        HttpCaller caller = HttpCaller.builder("gateway", stamper).bundle(policy.bundles().get("gateway"))
                .verifier(gatewayVerifier()).build();
        RequestContext.addInfluence(MINE); // written by unscoped code; must not be committed either

        for (int i = 0; i < 2; i++) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);
            assertNull(sent.headers().get(PaztportHeaders.INFLUENCE));
            assertEquals("", chainOf(sent.headers()).get(0).infl());
            caller.recordToContext(sent, 200,
                    attestation(sent, "hello", List.of(ContentLabel.fresh(InfluenceClass.PRIVATE, "alice"))),
                    utf8("hello"));
        }

        assertEquals(List.of(MINE), RequestContext.influence(), "neither response was recorded");
        assertEquals(2, traceLines().size());
        assertTrue(traceLines().stream().allMatch(l -> l.contains(" reason=OK ") && l.contains("labels=private")),
                "both verified and carried alice's label, so there was something to leak: " + traceLines());
    }

    // The function answers what a response contributes and leaves recording it to the binding.
    @Test
    void checkAnswersTheEntriesAndRecordsNothing() {
        HttpCaller caller = verifyingCaller();
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);

            HttpCaller.Received received = caller.check(sent, 502, null, utf8("bad gateway"));

            assertEquals(ReasonCode.CHAIN_MISSING, received.check().result().reason());
            assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                    HttpV3.resultHash(502, utf8("bad gateway")), null, null)), received.influence());
            assertEquals(List.of(), RequestContext.influence(), "nothing is recorded by the function");
        }
    }

    // --- The two layers do not mix ---

    // Inside a scope the binding cannot tell whose work a call the function stamped was, so it refuses it rather
    // than drop what its response adds, before the check, which leaves the response's nonce for check to take.
    @Test
    void aCallNotStampedFromTheContextIsRefusedInsideAScope() {
        ContentLabel web = ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null);
        HttpCaller caller = verifyingCaller();
        HttpCaller.Outbound early = caller.stampFromContext("GET", ORDERS, NO_BODY); // before the scope opened
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stamp("GET", ORDERS, NO_BODY, null, List.of());
            String attested = attestation(sent, "hello", List.of(web));

            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> caller.recordToContext(sent, 200, attested, utf8("hello")));
            assertThrows(IllegalStateException.class,
                    () -> caller.recordToContext(early, 500, null, utf8("boom")));

            assertTrue(e.getMessage().contains("not stamped from the request's context"), e.getMessage());
            assertTrue(e.getMessage().contains("check"), e.getMessage());
            assertEquals(List.of(), traceLines(), "refused before anything is checked or logged");
            assertEquals(List.of(), RequestContext.influence(), "nor recorded");
            assertEquals(ReasonCode.OK, caller.check(sent, 200, attested, utf8("hello")).check().result().reason(),
                    "the response's nonce is still unspent");
        }
    }

    @Test
    void aCallStampedFromTheContextIsRecordedToIt() {
        HttpCaller caller = verifyingCaller();
        try (RequestContext.Scope scope = RequestContext.open()) {
            HttpCaller.Outbound sent = caller.stampFromContext("GET", ORDERS, NO_BODY);

            assertDoesNotThrow(() -> caller.recordToContext(sent, 502, null, utf8("bad gateway")));

            assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                    HttpV3.resultHash(502, utf8("bad gateway")), null, null)), RequestContext.influence());
        }
    }

    @Test
    void outsideAScopeACallTheFunctionStampedIsCheckedAndNotRecorded() {
        HttpCaller caller = verifyingCaller();
        HttpCaller.Outbound sent = caller.stamp("GET", ORDERS, NO_BODY, null, List.of());

        HttpV3.ResponseCheck check = assertDoesNotThrow(
                () -> caller.recordToContext(sent, 502, null, utf8("bad gateway")));

        assertEquals(ReasonCode.CHAIN_MISSING, check.result().reason());
        assertEquals(List.of(), RequestContext.influence());
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=CHAIN_MISSING receiver=gateway ✗ labels=-"),
                traceLines());
    }
}
