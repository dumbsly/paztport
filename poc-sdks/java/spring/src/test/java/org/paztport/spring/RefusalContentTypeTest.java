// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.ModeHolder;
import org.paztport.http.RequestContext;
import org.paztport.http.VerificationMode;
import org.paztport.http.wire.HttpV3;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.outbound.OutboundInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.CharacterEncodingFilter;

/**
 * A mesh refusal on the real servlet container, header and body as the wire carries them: {@code Content-Type:
 * application/json} and nothing after it, because the container adds a character encoding of its own to anything
 * written through a writer, and RFC 8259 defines no such parameter. The partner's refusals are checked the same way
 * in {@code PartnerRequestTest}. The app is {@code localhost}, as in {@code ResponseAttestationTest}, whose set-up
 * this follows. The application also registers a forcing {@code CharacterEncodingFilter}, as an application may,
 * which runs before Paztport's filters and which a refusal must still not carry.
 */
@SpringBootTest(classes = RefusalContentTypeTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.banner-mode=off")
class RefusalContentTypeTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair APP = Crypto.generateEd25519KeyPair();
    private static final HttpClient http = TestHttp.newClient();
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-refusal-type");
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        PolicyBuilder.Result built =
                PolicyBuilder.build(List.of(List.of("localhost", "localhost")), 4, NOT_AFTER, policy.getPrivate());

        Files.writeString(trust.resolve("localhost.key"), Base64Url.encode(Crypto.encodePrivateKey(APP.getPrivate())));
        Files.writeString(trust.resolve("policy.pub"), policyPub);
        JSON.writeValue(trust.resolve("keyring.json").toFile(), KeyringFile.sign(
                Map.of("localhost", Base64Url.encode(Crypto.encodePublicKey(APP.getPublic()))), policyPub, NOT_AFTER,
                policy.getPrivate()));
        JSON.writeValue(trust.resolve("root.json").toFile(), built.signedRoot());
        JSON.writeValue(trust.resolve("proofs-localhost.json").toFile(), built.bundles().get("localhost"));

        registry.add("paztport.service-name", () -> "localhost");
        registry.add("paztport.instance", () -> "localhost-1");
        registry.add("paztport.verify", () -> "true");
        registry.add("paztport.origins", () -> "localhost");
        registry.add("paztport.key-path", () -> trust.resolve("localhost.key").toString());
        registry.add("paztport.proofs-path", () -> trust.resolve("proofs-localhost.json").toString());
        registry.add("paztport.keyring-path", () -> trust.resolve("keyring.json").toString());
        registry.add("paztport.root-path", () -> trust.resolve("root.json").toString());
        registry.add("paztport.policy-key-path", () -> trust.resolve("policy.pub").toString());
    }

    @AfterAll
    static void removeTrustFiles() throws IOException {
        http.close();
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Handlers.class)
    static class App {

        /** Sets UTF-8 on every response ahead of Paztport's filters, as a forcing encoding filter does. */
        @Bean
        FilterRegistrationBean<CharacterEncodingFilter> forcedEncoding() {
            FilterRegistrationBean<CharacterEncodingFilter> bean =
                    new FilterRegistrationBean<>(new CharacterEncodingFilter("UTF-8", false, true));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return bean;
        }
    }

    @RestController
    static class Handlers {
        @GetMapping("/orders")
        String orders() {
            return "orders";
        }
    }

    @LocalServerPort
    private int port;

    @Autowired
    private VerifierV3 verifier;

    @Autowired
    private ProofBundle bundle;

    @Autowired
    private ModeHolder mode;

    @AfterEach
    void backToEnforce() {
        mode.set(VerificationMode.ENFORCE);
    }

    /** The origin's client, claiming influence the stamp never committed to, or none that parses, as given. */
    private RestClient client(String influenceHeader) {
        return TestHttp.restClient(http).requestInterceptor(new OutboundInterceptor(
                new StamperV3("localhost", "origin-1", APP.getPrivate(), true, () -> UUID.randomUUID().toString(),
                        System::currentTimeMillis), bundle, verifier, "localhost"))
                .requestInterceptor((request, body, execution) -> {
                    request.getHeaders().set(PaztportHeaders.INFLUENCE, influenceHeader);
                    return execution.execute(request, body);
                }).build();
    }

    private record Answer(int status, byte[] body, List<String> types) {
    }

    private Answer call(String influenceHeader) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            return client(influenceHeader).get().uri(URI.create("http://localhost:" + port + "/orders"))
                    .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                            response.getBody().readAllBytes(), response.getHeaders().getOrEmpty("Content-Type")),
                            false);
        }
    }

    @Test
    void anEnforcedMeshRefusalIsPlainApplicationJson() {
        String claimed = HttpV3.encodeInfluence(List.of(
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null)));

        Answer refused = call(claimed);

        assertEquals(403, refused.status());
        assertArrayEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}".getBytes(StandardCharsets.UTF_8), refused.body());
        assertEquals(List.of("application/json"), refused.types());
    }

    @Test
    void anAuditedUnreadableInfluenceRefusalIsPlainApplicationJson() {
        mode.set(VerificationMode.AUDIT);

        Answer refused = call("%%%");

        assertEquals(400, refused.status());
        assertArrayEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}".getBytes(StandardCharsets.UTF_8), refused.body());
        assertEquals(List.of("application/json"), refused.types());
    }
}
