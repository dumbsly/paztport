// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import static io.micrometer.observation.tck.TestObservationRegistryAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.tck.TestObservationRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/**
 * What the interceptor records about each response it checks: one observation, tagged with the check's reason and
 * nothing else, stopped when the check is done. Nothing from the response is ever a tag. What is checked, and so
 * what is recorded, is {@code OutboundInterceptorTest}'s and {@code HttpCallerTest}'s; the cases here read the
 * registry.
 */
class ResponseObservationTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private final TestObservationRegistry registry = TestObservationRegistry.create();
    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders")), 4, NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());

    private Verifier gatewayVerifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> 2500L, 5000, 5000));
    }

    private OutboundInterceptor interceptor(Verifier verifier) {
        return interceptor(verifier, registry);
    }

    private OutboundInterceptor interceptor(Verifier verifier, ObservationRegistry observations) {
        return new OutboundInterceptor(
                new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> 1000L),
                policy.bundles().get("gateway"), verifier, "gateway", observations);
    }

    /** A RestClient carrying {@code interceptor}, whose one expected call to orders is answered by {@code answer}. */
    private static RestClient client(OutboundInterceptor interceptor, ResponseCreator answer) {
        RestClient.Builder builder = RestClient.builder().requestInterceptor(interceptor);
        MockRestServiceServer.bindTo(builder).build()
                .expect(requestTo("http://orders:8080/orders")).andRespond(answer);
        return builder.build();
    }

    /** Orders' answer: {@code hello} with an attestation over it, as orders' filter would send it. */
    private ResponseCreator attested() {
        return request -> {
            HttpHeaders sent = request.getHeaders();
            List<Stamp> inbound = Chains.parse(HttpWire.decodeChain(sent.getFirst(PaztportHeaders.CHAIN))).stamps();
            String hash = HttpWire.resultHash(200, "hello".getBytes(StandardCharsets.UTF_8));
            List<ContentLabel> labels = List.of(ContentLabel.fresh(InfluenceClass.THIRD_PARTY, null));
            Stamp stamp = new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> 2000L)
                    .respond(inbound, hash, inbound.get(0).rid(), labels);
            return withSuccess("hello", MediaType.TEXT_PLAIN)
                    .header(PaztportHeaders.RESPONSE, HttpWire.encodeResponse(stamp, labels))
                    .createResponse(request);
        };
    }

    private static void fetch(RestClient client) {
        client.get().uri("http://orders:8080/orders").retrieve().toBodilessEntity();
    }

    private static void fetchInScope(RestClient client) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            fetch(client);
        }
    }

    @Test
    void aVerifiedResponseRecordsOk() {
        fetchInScope(client(interceptor(gatewayVerifier()), attested()));

        assertThat(registry).hasNumberOfObservationsEqualTo(1)
                .hasSingleObservationThat()
                .hasNameEqualTo("paztport.response")
                .hasLowCardinalityKeyValue("reason", "OK")
                .doesNotHaveError()
                .hasBeenStopped();
    }

    @Test
    void anUnattestedResponseRecordsItsCode() {
        fetchInScope(client(interceptor(gatewayVerifier()), withSuccess("hello", MediaType.TEXT_PLAIN)));

        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("reason", "CHAIN_MISSING")
                .doesNotHaveError()
                .hasBeenStopped();
    }

    @Test
    void noVerifierRecordsNone() {
        fetchInScope(client(interceptor(null), withSuccess("hello", MediaType.TEXT_PLAIN)));

        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("reason", "none")
                .doesNotHaveError()
                .hasBeenStopped();
    }

    @Test
    void onlyTheReasonIsRecorded() {
        fetchInScope(client(interceptor(gatewayVerifier()), attested()));

        assertThat(registry).hasSingleObservationThat().hasOnlyKeys("reason");
    }

    @Test
    void aRefusedRecordStopsWithTheError() {
        // The scope has ended by the time the response arrives, so the caller refuses to record it.
        RequestContext.Scope[] open = new RequestContext.Scope[1];
        RestClient client = client(interceptor(gatewayVerifier()), request -> {
            open[0].close();
            return attested().createResponse(request);
        });

        IllegalStateException thrown;
        try (RequestContext.Scope scope = RequestContext.open()) {
            open[0] = scope;
            thrown = assertThrows(IllegalStateException.class, () -> fetch(client));
        }

        assertThat(registry).hasNumberOfObservationsEqualTo(1)
                .hasSingleObservationThat()
                .hasError(thrown)
                .hasLowCardinalityKeyValue("reason", "none")
                .hasOnlyKeys("reason")
                .hasBeenStopped();
    }

    @Test
    void onlyTheCheckIsObserved() {
        RestClient failing = client(interceptor(gatewayVerifier()), request -> {
            throw new IOException("connection reset");
        });

        assertThrows(ResourceAccessException.class, () -> fetchInScope(failing));
        assertThat(registry).hasNumberOfObservationsEqualTo(0);

        fetchInScope(client(interceptor(gatewayVerifier()), attested()));
        assertThat(registry).hasNumberOfObservationsEqualTo(1).hasSingleObservationThat().hasBeenStopped();
    }

    // The response holds the connection: an error while its check is recorded must still release it.
    @Test
    void anErrorWhileRecordingClosesTheResponse() {
        Error failure = new Error("handler failed");
        ObservationRegistry throwing = ObservationRegistry.create();
        throwing.observationConfig().observationHandler(new ObservationHandler<>() {
            @Override
            public void onStop(Observation.Context context) {
                throw failure;
            }

            @Override
            public boolean supportsContext(Observation.Context context) {
                return true;
            }
        });
        boolean[] closed = {false};
        RestClient client = client(interceptor(gatewayVerifier(), throwing), request -> {
            ClientHttpResponse answer = withSuccess("hello", MediaType.TEXT_PLAIN).createResponse(request);
            return new ClientHttpResponse() {
                @Override
                public HttpStatusCode getStatusCode() throws IOException {
                    return answer.getStatusCode();
                }

                @Override
                public String getStatusText() throws IOException {
                    return answer.getStatusText();
                }

                @Override
                public HttpHeaders getHeaders() {
                    return answer.getHeaders();
                }

                @Override
                public InputStream getBody() throws IOException {
                    return answer.getBody();
                }

                @Override
                public void close() {
                    closed[0] = true;
                    answer.close();
                }
            };
        });

        Error thrown = assertThrows(Error.class, () -> fetchInScope(client));

        assertSame(failure, thrown);
        assertTrue(closed[0], "the connection is released even though recording the check failed");
    }
}
