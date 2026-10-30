// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.HttpCaller;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.http.RequestContext;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
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
    private VerifierV3 gatewayVerifier() {
        return new VerifierV3(new VerifierConfigV3(
                Keyring.of(Map.of("gateway", gateway.getPublic(), "orders", orders.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), policy.signedRoot().notAfter(),
                Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> 2500L, 5000, 5000));
    }

    private OutboundInterceptor gatewayInterceptor() {
        return new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), null, "gateway");
    }

    private StamperV3 gatewayStamper() {
        return new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L);
    }

    private StamperV3 ordersStamper() {
        return new StamperV3("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 2000L);
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
            List<StampV3> inbound = chainOf(request.getHeaders());
            String hash = HttpV3.resultHash(200, attested.getBytes(StandardCharsets.UTF_8));
            StampV3 stamp = ordersStamper().respond(inbound, hash, inbound.get(0).rid(), labels);
            return withSuccess(body, MediaType.TEXT_PLAIN)
                    .header(PaztportHeaders.RESPONSE, HttpV3.encodeResponse(stamp, labels))
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

    private static List<StampV3> chainOf(HttpHeaders headers) {
        List<RecordedStamp> stamps = Chains.parse(HttpV3.decodeChain(headers.getFirst(PaztportHeaders.CHAIN)), false)
                .stamps();
        return stamps.stream().map(StampV3.class::cast).toList();
    }

    @Test
    void appendsToTheInboundChainCommittingTheContextInfluence() {
        StamperV3.Stamped received = gatewayStamper().next(null, "orders", "b", List.of(),
                policy.bundles().get("gateway"));
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInboundChain(received.chain());
            RequestContext.addInfluence(MINE, WEB);

            client(new OutboundInterceptor(ordersStamper(), policy.bundles().get("orders"), null, "orders"),
                    "http://payment:8080/pay")
                    .post().uri("http://payment:8080/pay").body("{\"amount\":1}").retrieve().toBodilessEntity();
        }

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
    void stampsForTheReceiverTheCallerNames() {
        HttpCaller caller = HttpCaller.builder("gateway", gatewayStamper()).bundle(policy.bundles().get("gateway"))
                .receivers(Map.of("orders-internal", "orders")).build();
        client(new OutboundInterceptor(caller), "http://orders-internal:8080/orders")
                .get().uri("http://orders-internal:8080/orders").retrieve().toBodilessEntity();

        assertEquals("orders", chainOf(sent.get(0)).get(0).rcv());
        assertNotNull(sent.get(0).getFirst(PaztportHeaders.PROOF), "the proof is for the route to orders");
    }

    // The RestClient encodes the space; the binding is over the query as it goes on the wire.
    @Test
    void bindsTheRawQuery() {
        client(gatewayInterceptor(),
                "http://search:8080/search?q=a%20b")
                .get().uri("http://search:8080/search?q=a b").retrieve().toBodilessEntity();

        StampV3 stamp = chainOf(sent.get(0)).get(0);
        assertEquals("search", stamp.rcv());
        assertEquals(RequestBinding.compute("GET", "/search?q=a%20b", new byte[0]), stamp.bind());
    }

    @Test
    void aVerifiedResponseRecordsItsLabelsAsInfluence() {
        ContentLabel mine = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        ContentLabel web = ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null);
        RestClient client = client(
                new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), gatewayVerifier(),
                        "gateway"),
                "http://orders:8080/orders", attested("hello", "hello", List.of(mine, web)));

        List<InfluenceEntry> recorded = fetchRecorded(client, "hello");

        String hash = HttpV3.resultHash(200, "hello".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of(mine.toEntry("http:orders", hash), web.toEntry("http:orders", hash)), recorded);
        assertEquals(List.of(), RequestContext.influence(), "closing the scope drops what it recorded");
        assertEquals(List.of(
                "PAZTPORT_TRACE response rid=rid-1 from=orders reason=OK receiver=gateway ✓ labels=private,third-party"),
                traceLines());
    }

    @Test
    void anUnattestedErrorIsBufferedAndUntrusted() {
        RestClient client = client(
                new OutboundInterceptor(gatewayStamper(), policy.bundles().get("gateway"), gatewayVerifier(),
                        "gateway"),
                "http://orders:8080/orders", withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("boom"));

        List<InfluenceEntry> recorded = fetchRecorded(client, "boom");

        assertEquals(List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:orders",
                HttpV3.resultHash(500, "boom".getBytes(StandardCharsets.UTF_8)), null, null)),
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
}
