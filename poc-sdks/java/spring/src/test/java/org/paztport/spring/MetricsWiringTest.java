// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.observation.ObservationRegistry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.CompositeMeterRegistryAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.MetricsAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.micrometer.observation.autoconfigure.ObservationAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Boot's own observation and metrics auto-configurations, with the starter's, turn what the filters and the
 * interceptor record into meters in Boot's registry; the standard property switches them off; and an application
 * without those auto-configurations is served exactly as before. What is recorded is
 * {@code RequestObservationTest}'s and {@code ResponseObservationTest}'s; the cases here show that Boot reads it.
 */
class MetricsWiringTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ApplicationContextRunner starter = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    PaztportAutoConfiguration.class, SslAutoConfiguration.class, RestClientAutoConfiguration.class));

    /** The starter beside Boot's observation and metrics auto-configurations, with its in-memory registry. */
    private final ApplicationContextRunner withBoot = starter.withConfiguration(AutoConfigurations.of(
            ObservationAutoConfiguration.class, MetricsAutoConfiguration.class,
            CompositeMeterRegistryAutoConfiguration.class, SimpleMetricsExportAutoConfiguration.class));

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private PolicyBuilder.Result built;

    /** A verifying payment service that is also an origin, so it stamps what it sends and checks the answers. */
    private String[] payment(Path dir) throws Exception {
        return payment(dir, true);
    }

    /**
     * A verifying payment service with a key to stamp with, behind a gateway that may call it; an origin
     * starts its own chains and ignores the one a request brings.
     */
    private String[] payment(Path dir, boolean origin) throws Exception {
        String policyKey = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Files.writeString(dir.resolve("payment.key"),
                Base64Url.encode(Crypto.encodePrivateKey(payment.getPrivate())));
        Files.writeString(dir.resolve("policy.pub"), policyKey + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(), KeyringFile.sign(
                Map.of("gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic())),
                        "payment", Base64Url.encode(Crypto.encodePublicKey(payment.getPublic()))), policyKey,
                NOT_AFTER, policy.getPrivate()));
        built = PolicyBuilder.build(List.of(List.of("gateway", "payment")), 4, NOT_AFTER,
                policy.getPrivate());
        JSON.writeValue(dir.resolve("root.json").toFile(), built.signedRoot());
        return new String[] {
            "paztport.service-name=payment", "paztport.verify=true", "paztport.origin=" + origin,
            "paztport.key-path=" + dir.resolve("payment.key"),
            "paztport.keyring-path=" + dir.resolve("keyring.json"),
            "paztport.root-path=" + dir.resolve("root.json"),
            "paztport.policy-key-path=" + dir.resolve("policy.pub")};
    }

    /** The request filter the starter registers, with nothing in the request that would verify. */
    @SuppressWarnings("unchecked")
    private static InboundFilter filter(ApplicationContext context) {
        return ((FilterRegistrationBean<InboundFilter>)
                context.getBean("inboundFilterRegistration", FilterRegistrationBean.class)).getFilter();
    }

    private static MockHttpServletResponse unverifiedRequest(ApplicationContext context) throws Exception {
        InboundFilter filter = filter(context);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setContent("{\"amount\":100}".getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void bootTurnsRequestsIntoATimer(@TempDir Path dir) throws Exception {
        withBoot.withPropertyValues(payment(dir)).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(unverifiedRequest(context).getStatus()).isEqualTo(403);

            Timer timer = context.getBean(MeterRegistry.class).get("paztport.request")
                    .tags("mode", "enforce", "reason", "CHAIN_MISSING", "outcome", "refused").timer();
            assertThat(timer.count()).isEqualTo(1);
            assertThat(timer.getId().getTags()).extracting(tag -> tag.getKey())
                    .containsExactlyInAnyOrder("mode", "reason", "outcome", "error");
        });
    }

    @Test
    void bootTurnsResponsesIntoATimer(@TempDir Path dir) throws Exception {
        withBoot.withPropertyValues(payment(dir)).run(context -> {
            RestClient.Builder builder = context.getBean(RestClient.Builder.class);
            MockRestServiceServer.bindTo(builder).build()
                    .expect(requestTo("http://orders:8080/orders"))
                    .andRespond(withSuccess("hello", MediaType.TEXT_PLAIN));
            try (RequestContext.Scope scope = RequestContext.open()) {
                builder.build().get().uri("http://orders:8080/orders").retrieve().toBodilessEntity();
            }

            Timer timer = context.getBean(MeterRegistry.class).get("paztport.response")
                    .tags("reason", "CHAIN_MISSING").timer();
            assertThat(timer.count()).isEqualTo(1);
            assertThat(timer.getId().getTags()).extracting(tag -> tag.getKey())
                    .containsExactlyInAnyOrder("reason", "error");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"paztport", "paztport.request"})
    void theStandardPropertySwitchesItOff(String name, @TempDir Path dir) throws Exception {
        withBoot.withPropertyValues(payment(dir))
                .withPropertyValues("management.observations.enable." + name + "=false")
                .run(context -> {
                    assertThat(unverifiedRequest(context).getStatus()).isEqualTo(403);

                    assertThat(context.getBean(MeterRegistry.class).find("paztport.request").meters()).isEmpty();
                });
    }

    @Test
    void withoutMicrometerNothingChanges(@TempDir Path dir) throws Exception {
        starter.withPropertyValues(payment(dir, false)).run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(MeterRegistry.class)
                    .doesNotHaveBean(ObservationRegistry.class);

            MockHttpServletResponse refused = unverifiedRequest(context);
            assertThat(refused.getStatus()).isEqualTo(403);
            assertThat(refused.getContentAsString()).contains("CHAIN_MISSING");

            byte[] body = "{\"amount\":100}".getBytes();
            Stamper.Stamped stamped = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1",
                    () -> System.currentTimeMillis())
                    .next(null, "payment", RequestBinding.compute("POST", "/pay", body), List.of(),
                            built.bundles().get("gateway"));
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
            request.addHeader(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
            request.addHeader(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
            request.setContent(body);
            MockHttpServletResponse served = new MockHttpServletResponse();
            filter(context).doFilter(request, served, new MockFilterChain());

            assertThat(served.getStatus()).isEqualTo(200);
            assertThat(served.getHeader(PaztportHeaders.RESPONSE)).isNotNull();
        });
    }
}
