// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import static io.micrometer.observation.tck.TestObservationRegistryAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.tck.TestObservationRegistry;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.HttpCaller;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/**
 * The interceptor's Spring part: the caller's headers go on the request as the RestClient sends it, the binding is
 * over the target as encoded on the wire, and the response is handed to the caller whole, then back to the
 * application from memory. What the stamp and the response check say is {@code HttpCallerTest}'s, in
 * {@code paztport-http}.
 */
class OutboundInterceptorTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders"),
                    List.of("gateway", "search")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

    /** The headers of every request the mock server received. */
    private final List<HttpHeaders> sent = new ArrayList<>();

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
    }

    private List<String> traceLines() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    /** What gateway uses to check the responses it gets: it trusts gateway and orders, and gateway is the origin. */
    private Verifier gatewayVerifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> 2500L, 5000, 5000));
    }

    private OutboundInterceptor gatewayInterceptor() {
        return new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), null, "gateway",
                ObservationRegistry.NOOP);
    }

    private Stamper gatewayStamper() {
        return new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L);
    }

    private Stamper ordersStamper() {
        return new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 2000L);
    }

    /** A RestClient carrying the interceptor, against a mock server expecting one request to {@code uri}. */
    private RestClient client(OutboundInterceptor interceptor, String uri) {
        return client(interceptor, uri, withSuccess());
    }

    /** As above, answering with whatever {@code answer} creates for the request it received. */
    private RestClient client(OutboundInterceptor interceptor, String uri, ResponseCreator answer) {
        RestClient.Builder builder = RestClient.builder().requestInterceptor(interceptor);
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(uri)).andRespond(request -> {
            sent.add(request.getHeaders());
            return answer.createResponse(request);
        });
        return builder.build();
    }

    /** Orders' answer: {@code body} with an attestation over {@code attested}, as orders' filter would send it. */
    private ResponseCreator attested(String body, String attested, List<ContentLabel> labels) {
        return request -> {
            List<Stamp> inbound = chainOf(request.getHeaders());
            String hash = HttpWire.resultHash(200, attested.getBytes(StandardCharsets.UTF_8));
            Stamp stamp = ordersStamper().respond(inbound, hash, inbound.get(0).rid(), labels);
            return withSuccess(body, MediaType.TEXT_PLAIN)
                    .header(PaztportHeaders.RESPONSE, HttpWire.encodeResponse(stamp, labels))
                    .createResponse(request);
        };
    }

    /** Calls orders through {@code client} and answers the body as text, whatever the status. */
    private static String fetchOrders(RestClient client) {
        return client.get().uri("http://orders:8080/orders").exchange((request, response) ->
                new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8), false);
    }

    /** Calls orders inside a context scope, checks the body, and answers what the call recorded. */
    private static List<InfluenceEntry> fetchRecorded(RestClient client, String expectedBody) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertEquals(expectedBody, fetchOrders(client), "the caller still reads the whole body");
            return RequestContext.influence();
        }
    }

    private static List<Stamp> chainOf(HttpHeaders headers) {
        return Chains.parse(HttpWire.decodeChain(headers.getFirst(PaztportHeaders.CHAIN))).stamps();
    }

    @Test
    void appendsToTheInboundChainCommittingTheContextInfluence() {
        Stamper.Stamped received = gatewayStamper().next(null, "orders", "b", List.of(),
                policy.bundles().get("gateway"));
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(received.chain());
            RequestContext.addInfluence(MINE, WEB);

            client(new OutboundInterceptor(ordersStamper(), policy.bundles().get("orders"), null, "orders",
                    ObservationRegistry.NOOP),
                    "http://payment:8080/pay")
                    .post().uri("http://payment:8080/pay").body("{\"amount\":1}").retrieve().toBodilessEntity();
        }

        List<Stamp> chain = chainOf(sent.get(0));
        assertEquals(2, chain.size());
        Stamp last = chain.get(1);
        assertEquals("orders", last.svc());
        assertEquals("payment", last.rcv());
        assertEquals(Influence.commit(List.of(MINE, WEB)), last.infl());
        assertEquals(RequestBinding.compute("POST", "/pay", "{\"amount\":1}".getBytes(StandardCharsets.UTF_8)),
                last.bind());
        assertEquals(List.of(MINE, WEB),
                Influence.parse(HttpWire.decodeInfluence(sent.get(0).getFirst(PaztportHeaders.INFLUENCE))));
        assertNotNull(sent.get(0).getFirst(PaztportHeaders.PROOF));
    }

    @Test
    void stampsForTheReceiverTheCallerNames() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway"))
                .receivers(Map.of("orders-internal", "orders")).build();
        client(new OutboundInterceptor(caller, ObservationRegistry.NOOP), "http://orders-internal:8080/orders")
                .get().uri("http://orders-internal:8080/orders").retrieve().toBodilessEntity();

        assertEquals("orders", chainOf(sent.get(0)).get(0).rcv());
        assertNotNull(sent.get(0).getFirst(PaztportHeaders.PROOF), "the proof is for the route to orders");
    }

    @Test
    void sendsOnlyThePaztportHeadersItStamped() {
        client(gatewayInterceptor(), "https://payment/x")
                .get().uri("https://payment/x")
                .header("X-Path-Proof", "p")
                .header("X-Path-Influence", "i")
                .header("x-path-session", "s")
                .header("X-Path-Future", "f")
                .header("x-path-chain", "c1", "c2")
                .header("X-Pathology", "kept")
                .retrieve().toBodilessEntity();

        HttpHeaders received = sent.get(0);
        assertEquals(1, received.get("X-Path-Chain").size(), "one chain value: the one the caller stamped");
        List<Stamp> chain = chainOf(received);
        assertEquals(1, chain.size());
        assertEquals("rid-1", chain.get(0).rid());
        assertEquals("gateway", chain.get(0).svc());
        assertEquals("payment", chain.get(0).rcv());
        assertNull(received.get("X-Path-Proof"), "the application's proof is not sent");
        assertNull(received.get("X-Path-Influence"), "the application's influence is not sent");
        assertNull(received.get("X-Path-Session"), "the application's session is not sent");
        assertNull(received.get("X-Path-Future"), "an unknown X-Path- header is not sent");
        assertEquals("kept", received.getFirst("X-Pathology"), "a header outside the prefix is the application's");
    }

    // The RestClient encodes the space; the binding is over the query as it goes on the wire.
    @Test
    void bindsTheRawQuery() {
        client(gatewayInterceptor(),
                "http://search:8080/search?q=a%20b")
                .get().uri("http://search:8080/search?q=a b").retrieve().toBodilessEntity();

        Stamp stamp = chainOf(sent.get(0)).get(0);
        assertEquals("search", stamp.rcv());
        assertEquals(RequestBinding.compute("GET", "/search?q=a%20b", new byte[0]), stamp.bind());
    }

    @Test
    void aVerifiedResponseRecordsItsLabelsAsInfluence() {
        ContentLabel mine = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        ContentLabel web = ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null);
        RestClient client = client(
                new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), gatewayVerifier(),
                        "gateway", ObservationRegistry.NOOP),
                "http://orders:8080/orders", attested("hello", "hello", List.of(mine, web)));

        List<InfluenceEntry> recorded = fetchRecorded(client, "hello");

        String hash = HttpWire.resultHash(200, "hello".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of(mine.toEntry("http:orders", hash), web.toEntry("http:orders", hash)), recorded);
        assertEquals(List.of(), RequestContext.influence(), "closing the scope drops what it recorded");
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓ "
                        + "labels=private,third-party"),
                traceLines());
    }

    @Test
    void anUnattestedErrorIsBufferedAndUntrusted() {
        RestClient client = client(
                new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), gatewayVerifier(),
                        "gateway", ObservationRegistry.NOOP),
                "http://orders:8080/orders", withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("boom"));

        List<InfluenceEntry> recorded = fetchRecorded(client, "boom");

        assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                HttpWire.resultHash(500, "boom".getBytes(StandardCharsets.UTF_8)), null, null)),
                recorded);
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=CHAIN_MISSING receiver=gateway ✗ labels=-"),
                traceLines());
    }

    @Test
    void aResponseThatCannotBeCheckedIsClosed() {
        boolean[] closed = {false};
        ClientHttpResponse broken = new ClientHttpResponse() {
            @Override
            public HttpStatusCode getStatusCode() throws IOException {
                throw new IOException("status line lost");
            }

            @Override
            public String getStatusText() {
                return "";
            }

            @Override
            public HttpHeaders getHeaders() {
                return new HttpHeaders();
            }

            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(new byte[0]);
            }

            @Override
            public void close() {
                closed[0] = true;
            }
        };
        RestClient client = client(gatewayInterceptor(), "http://orders:8080/orders", request -> broken);

        assertThrows(ResourceAccessException.class, () -> fetchOrders(client));
        assertTrue(closed[0], "the connection is released even though the response could not be checked");
    }

    // Not every failure to read a response is an IOException: a client library may throw an unchecked one.
    @Test
    void aResponseWhoseBodyFailsUncheckedIsClosed() {
        IllegalStateException failure = new IllegalStateException("body lost");
        boolean[] closed = {false};
        ClientHttpResponse broken = new ClientHttpResponse() {
            @Override
            public HttpStatusCode getStatusCode() {
                return HttpStatus.OK;
            }

            @Override
            public String getStatusText() {
                return "OK";
            }

            @Override
            public HttpHeaders getHeaders() {
                return new HttpHeaders();
            }

            @Override
            public InputStream getBody() {
                throw failure;
            }

            @Override
            public void close() {
                closed[0] = true;
            }
        };
        RestClient client = client(gatewayInterceptor(), "http://orders:8080/orders", request -> broken);

        IllegalStateException thrown = assertThrows(IllegalStateException.class, () -> fetchOrders(client));

        assertSame(failure, thrown);
        assertTrue(closed[0], "the connection is released even though the body could not be read");
    }

    // --- Retrying a call that never connected ---

    /** The time the retry measures the origin stamp's age at: 4500 ms after gateway's stamps. */
    private static final long NOW = 5500L;

    /** A 1000 ms connect timeout and a 5000 ms origin window, at {@code now}. */
    private static UnconnectedRetry retryAt(long now) {
        return new UnconnectedRetry(Duration.ofMillis(1000), 5000,
                Clock.fixed(Instant.ofEpochMilli(now), ZoneOffset.UTC));
    }

    /** A connect timeout as the JDK's client gives it: with the {@code ConnectException} it ended as its cause. */
    private static HttpConnectTimeoutException connectTimeout() {
        HttpConnectTimeoutException e = new HttpConnectTimeoutException("HTTP connect timed out");
        e.initCause(new ConnectException("HTTP connect timed out"));
        return e;
    }

    /** Gateway's stamper with a clock that moves on a millisecond per stamp, so no two stamps it signs are alike. */
    private Stamper movingGatewayStamper() {
        AtomicLong clock = new AtomicLong(1000);
        return new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", clock::getAndIncrement);
    }

    /** Gateway checking its responses, retrying with {@code retry}, observed by {@code registry}. */
    private OutboundInterceptor gatewayRetrying(TestObservationRegistry registry, UnconnectedRetry retry) {
        return new OutboundInterceptor(HttpCaller.builder("gateway", movingGatewayStamper())
                .bundle(policy.bundles().get("gateway")).verifier(gatewayVerifier()).build(), registry, retry);
    }

    /**
     * An execution that throws each of its failures in turn and then answers as {@code answer} does, keeping the
     * target and a copy of the headers of every request it is given.
     */
    private static final class Attempts implements ClientHttpRequestExecution {
        final List<URI> targets = new ArrayList<>();
        final List<HttpHeaders> headers = new ArrayList<>();
        private final Deque<IOException> failures;
        private final ResponseCreator answer;

        Attempts(ResponseCreator answer, IOException... failures) {
            this.answer = answer;
            this.failures = new ArrayDeque<>(List.of(failures));
        }

        @Override
        public ClientHttpResponse execute(HttpRequest request, byte[] body) throws IOException {
            targets.add(request.getURI());
            headers.add(HttpHeaders.copyOf(request.getHeaders()));
            if (!failures.isEmpty()) {
                throw failures.pop();
            }
            MockClientHttpRequest received = new MockClientHttpRequest(request.getMethod(), request.getURI());
            received.getHeaders().putAll(request.getHeaders());
            return answer.createResponse(received);
        }
    }

    /** Sends a GET to {@code uri} through {@code interceptor} and {@code attempts}, and reads the body whole. */
    private static String get(OutboundInterceptor interceptor, String uri, Attempts attempts) throws IOException {
        try (ClientHttpResponse response = interceptor.intercept(
                new MockClientHttpRequest(HttpMethod.GET, URI.create(uri)), new byte[0], attempts)) {
            return new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Stamp lastStamp(HttpHeaders headers) {
        List<Stamp> chain = chainOf(headers);
        return chain.get(chain.size() - 1);
    }

    private static void assertRetryObserved(TestObservationRegistry registry, String failure, String outcome) {
        assertThat(registry).hasNumberOfObservationsWithNameEqualTo("paztport.outbound.retry", 1)
                .hasObservationWithNameEqualTo("paztport.outbound.retry").that()
                .hasLowCardinalityKeyValue("failure", failure).hasLowCardinalityKeyValue("outcome", outcome)
                .doesNotHaveError().hasBeenStopped();
    }

    /** Asserts that the retry sent the same request again, freshly stamped, and its response was checked. */
    private void assertRetriedFreshlyStamped(Attempts attempts, String body) {
        assertEquals("hello", body);
        assertEquals(2, attempts.headers.size(), "one retry");
        assertEquals(1, attempts.headers.get(1).get(PaztportHeaders.CHAIN).size(), "the first stamp is replaced");
        Stamp first = lastStamp(attempts.headers.get(0));
        Stamp second = lastStamp(attempts.headers.get(1));
        assertEquals(first.rid(), second.rid());
        assertEquals(first.rcv(), second.rcv());
        assertEquals(first.bind(), second.bind());
        assertTrue(second.ts() >= first.ts(), "the retry's stamp is signed afresh");
        assertNotEquals(first.sig(), second.sig());
    }

    @Test
    void retriesAConnectTimeoutOnceWithAFreshStamp() throws IOException {
        TestObservationRegistry registry = TestObservationRegistry.create();
        Attempts attempts = new Attempts(attested("hello", "hello", List.of()), connectTimeout());

        String body = get(gatewayRetrying(registry, retryAt(NOW)), "http://orders:8080/orders", attempts);

        assertRetriedFreshlyStamped(attempts, body);
        assertRetryObserved(registry, "connect_timeout", "retried");
        // Orders answered the second stamp: a check against the first would fail on the response's prev.
        assertEquals(List.of(
                "PAZTPORT_TRACE retry rid=rid-1 receiver=orders failure=connect_timeout outcome=retried",
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓ labels=-"),
                traceLines());
    }

    @Test
    void retriesARefusedConnectAndAFailedHandshake() throws IOException {
        Map<String, IOException> failures = Map.of(
                "connect", new ConnectException("Connection refused"),
                "handshake", new SSLHandshakeException("Remote host terminated the handshake"));
        for (Map.Entry<String, IOException> failure : failures.entrySet()) {
            traces.list.clear();
            TestObservationRegistry registry = TestObservationRegistry.create();
            Attempts attempts = new Attempts(attested("hello", "hello", List.of()), failure.getValue());

            String body = get(gatewayRetrying(registry, retryAt(NOW)), "http://orders:8080/orders", attempts);

            assertRetriedFreshlyStamped(attempts, body);
            assertRetryObserved(registry, failure.getKey(), "retried");
            assertEquals(List.of(
                    "PAZTPORT_TRACE retry rid=rid-1 receiver=orders failure=" + failure.getKey() + " outcome=retried",
                    "PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓ labels=-"),
                    traceLines());
        }
    }

    // Each of these may have reached orders, so sending it again could deliver it twice.
    @Test
    void neverRetriesAfterTheConnection() {
        for (IOException failure : List.of(new HttpTimeoutException("request timed out"),
                new IOException("HTTP/1.1 header parser received no bytes"), new ClosedChannelException())) {
            TestObservationRegistry registry = TestObservationRegistry.create();
            Attempts attempts = new Attempts(withSuccess(), failure);

            IOException thrown = assertThrows(IOException.class,
                    () -> get(gatewayRetrying(registry, retryAt(NOW)), "http://orders:8080/orders", attempts));

            assertSame(failure, thrown);
            assertEquals(1, attempts.headers.size(), failure.toString());
            assertThat(registry).doesNotHaveAnyObservation();
        }
        assertEquals(List.of(), traceLines());
    }

    @Test
    void secondFailureSurfacesWithTheFirstSuppressed() {
        TestObservationRegistry registry = TestObservationRegistry.create();
        IOException first = connectTimeout();
        IOException second = new ConnectException("Connection refused");
        Attempts attempts = new Attempts(withSuccess(), first, second);

        IOException thrown = assertThrows(IOException.class,
                () -> get(gatewayRetrying(registry, retryAt(NOW)), "http://orders:8080/orders", attempts));

        assertSame(second, thrown);
        assertArrayEquals(new Throwable[] {first}, thrown.getSuppressed());
        assertEquals(2, attempts.headers.size(), "one retry, however the retry fails");
        assertRetryObserved(registry, "connect_timeout", "retried");
    }

    @Test
    void skipsAHopelessRetry() {
        TestObservationRegistry registry = TestObservationRegistry.create();
        OutboundInterceptor interceptor = new OutboundInterceptor(HttpCaller.builder("orders", ordersStamper())
                .bundle(policy.bundles().get("orders")).build(), registry, retryAt(NOW));
        IOException failure = connectTimeout();
        Attempts attempts = new Attempts(withSuccess(), failure);

        try (RequestContext.Scope scope = RequestContext.open()) {
            // Gateway's stamp is 4500 ms old: with a 1000 ms connect the retry could arrive only after 5000 ms.
            RequestContext.setInboundChain(gatewayStamper().next(null, "orders", "b", List.of(),
                    policy.bundles().get("gateway")).chain());

            IOException thrown = assertThrows(IOException.class,
                    () -> get(interceptor, "http://payment:8080/pay", attempts));

            assertSame(failure, thrown, "the connect failure surfaces, not the receiver's EXPIRED");
        }
        assertEquals(1, attempts.headers.size());
        assertRetryObserved(registry, "connect_timeout", "skipped");
        assertEquals(List.of("PAZTPORT_TRACE retry rid=rid-1 receiver=payment failure=connect_timeout outcome=skipped"),
                traceLines());
    }

    // Outside a scope, and at the origin inside one, the retry's stamp is the origin's, so no window has run.
    @Test
    void retriesOutsideAScope() throws IOException {
        UnconnectedRetry late = retryAt(1_000_000L);
        Attempts outside = new Attempts(attested("hello", "hello", List.of()), connectTimeout());

        assertRetriedFreshlyStamped(outside,
                get(gatewayRetrying(TestObservationRegistry.create(), late), "http://orders:8080/orders", outside));

        Attempts atTheOrigin = new Attempts(attested("hello", "hello", List.of()), connectTimeout());
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertRetriedFreshlyStamped(atTheOrigin, get(gatewayRetrying(TestObservationRegistry.create(), late),
                    "http://orders:8080/orders", atTheOrigin));
        }
    }

    @Test
    void retryKeepsTheOperationAndKey() throws IOException {
        OperationTable keyed = new OperationTable("orders", List.of(
                new OperationTable.Operation("reserve", "POST", "/items/{}/reserve", null,
                        OperationTable.Key.segment(1))));
        PolicyBuilder.Result keysPolicy = PolicyBuilder.build(
                List.of(List.of("gateway", "orders#reserve"), List.of("gateway", "orders")), 4, NOT_AFTER,
                Crypto.generateEd25519KeyPair().getPrivate());
        OutboundInterceptor interceptor = new OutboundInterceptor(HttpCaller.builder("gateway", movingGatewayStamper())
                .bundle(keysPolicy.bundles().get("gateway")).operations(List.of(keyed)).build(),
                TestObservationRegistry.create(), retryAt(NOW));
        Attempts attempts = new Attempts(withSuccess(), connectTimeout());

        URI target = URI.create("http://orders:8080/items/A1/reserve");
        interceptor.intercept(new MockClientHttpRequest(HttpMethod.POST, target), new byte[0], attempts).close();

        assertEquals(List.of(target, target), attempts.targets);
        assertEquals("orders#reserve", lastStamp(attempts.headers.get(0)).rcv());
        assertEquals("orders#reserve", lastStamp(attempts.headers.get(1)).rcv());
        assertEquals(lastStamp(attempts.headers.get(0)).bind(), lastStamp(attempts.headers.get(1)).bind());
    }

    // A metrics handler that fails does not hide the connect failure, and the call is not sent again.
    @Test
    void aRetryObservationThatThrowsLetsTheConnectFailureGoOn() {
        IllegalStateException broken = new IllegalStateException("handler broke");
        ObservationRegistry throwing = ObservationRegistry.create();
        throwing.observationConfig().observationHandler(new ObservationHandler<>() {
            @Override
            public void onStop(Observation.Context context) {
                throw broken;
            }

            @Override
            public boolean supportsContext(Observation.Context context) {
                return true;
            }
        });
        OutboundInterceptor interceptor = new OutboundInterceptor(HttpCaller.builder("gateway", movingGatewayStamper())
                .bundle(policy.bundles().get("gateway")).build(), throwing, retryAt(NOW));
        IOException failure = connectTimeout();
        Attempts attempts = new Attempts(withSuccess(), failure);

        IOException thrown = assertThrows(IOException.class,
                () -> get(interceptor, "http://orders:8080/orders", attempts));

        assertSame(failure, thrown);
        assertArrayEquals(new Throwable[] {broken}, thrown.getSuppressed());
        assertEquals(1, attempts.headers.size());
    }

    @Test
    void offWhenDisabled() {
        TestObservationRegistry registry = TestObservationRegistry.create();
        OutboundInterceptor interceptor = new OutboundInterceptor(HttpCaller.builder("gateway", movingGatewayStamper())
                .bundle(policy.bundles().get("gateway")).build(), registry, null);
        IOException failure = connectTimeout();
        Attempts attempts = new Attempts(withSuccess(), failure);

        assertSame(failure, assertThrows(IOException.class,
                () -> get(interceptor, "http://orders:8080/orders", attempts)));
        assertEquals(1, attempts.headers.size());
        assertThat(registry).hasNumberOfObservationsWithNameEqualTo("paztport.outbound.retry", 0);
    }

    // Spring's interceptor chain builds a new request from the factory on each execute, so a retry is sent afresh.
    @Test
    void retriesThroughTheRestClientsChain() {
        AtomicInteger created = new AtomicInteger();
        List<HttpHeaders> sentOnTheWire = new ArrayList<>();
        ClientHttpRequestFactory factory = (uri, method) -> new MockClientHttpRequest(method, uri) {
            private final int attempt = created.incrementAndGet();

            @Override
            protected ClientHttpResponse executeInternal() throws IOException {
                sentOnTheWire.add(HttpHeaders.copyOf(getHeaders()));
                if (attempt == 1) {
                    throw connectTimeout();
                }
                return new MockClientHttpResponse("hello".getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
            }
        };
        RestClient client = RestClient.builder().requestFactory(factory)
                .requestInterceptor(gatewayRetrying(TestObservationRegistry.create(), retryAt(NOW))).build();

        assertEquals("hello", client.get().uri("http://orders:8080/orders").retrieve().body(String.class));
        assertEquals(2, created.get(), "each attempt is a request of its own from the factory");
        assertNotEquals(lastStamp(sentOnTheWire.get(0)).sig(), lastStamp(sentOnTheWire.get(1)).sig());
    }
}
