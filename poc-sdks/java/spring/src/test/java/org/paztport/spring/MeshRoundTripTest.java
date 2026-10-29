// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierV3;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * The real RestClient and the real servlet container, end to end: the outbound interceptor binds the raw target it
 * sends and the inbound filter binds the raw target the container hands it, so a percent-encoded query must come
 * out the same on both sides. The app is named {@code localhost}, because the interceptor takes the receiver from
 * the URI host; it is a verifying hop, and the test plays the origin that calls it, under the same name and key.
 * The keys, signed keyring, pin and policy are generated for each run.
 *
 * <p>The app does not call itself: a non-origin calling itself within one request tree would send the same
 * request nonce key twice, which the documented limit (a service calls a given receiver at most once per request
 * tree) rules out.
 */
@SpringBootTest(classes = MeshRoundTripTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.banner-mode=off")
class MeshRoundTripTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair APP = Crypto.generateEd25519KeyPair();
    private static final String ADMIN_TOKEN = "admin-" + UUID.randomUUID();
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-mesh");
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
        registry.add("paztport.admin-token", () -> ADMIN_TOKEN);
    }

    @AfterAll
    static void removeTrustFiles() throws IOException {
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(SearchController.class)
    static class App {
    }

    @RestController
    static class SearchController {
        @GetMapping("/search")
        Map<String, String> search(@RequestParam String q) {
            return Map.of("q", q);
        }
    }

    @LocalServerPort
    private int port;

    @Autowired
    private VerifierV3 verifier;

    @Autowired
    private ProofBundle bundle;

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
    void stopCapturing() {
        traceLog.detachAppender(traces);
        traceLog.setLevel(null);
        traceLog.setAdditive(true);
    }

    @Test
    void encodedQueryVerifies() {
        Map<String, String> body;
        try (HttpClient http = TestHttp.newClient()) {
            RestClient origin = TestHttp.restClient(http).requestInterceptor(new OutboundInterceptor(
                    new StamperV3("localhost", "origin-1", APP.getPrivate(), true,
                            () -> UUID.randomUUID().toString(), System::currentTimeMillis), bundle, verifier,
                    "localhost")).build();
            body = origin.get()
                    .uri(URI.create("http://localhost:" + port + "/search?q=caf%C3%A9%20x"))
                    .retrieve().body(new ParameterizedTypeReference<>() { });
        }

        assertEquals(Map.of("q", "café x"), body);
        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        List<String> requests = lines.stream().filter(l -> l.startsWith("PAZTPORT_TRACE request ")).toList();
        List<String> responses = lines.stream().filter(l -> l.startsWith("PAZTPORT_TRACE response ")).toList();
        assertEquals(1, requests.size(), lines.toString());
        assertTrue(requests.get(0).contains(" reason=OK receiver=localhost ✓ peer=none "), requests.get(0));
        // The answer comes back attested, since the chain verified, and the caller verifies it.
        assertEquals(1, responses.size(), lines.toString());
        assertTrue(responses.get(0).contains(" from=localhost reason=OK receiver=localhost ✓ "), responses.get(0));
    }

    /**
     * The control channel's answers through the real container, byte for byte. Spring MVC writes them from maps of
     * strings, so a change in how the framework serialises a body would show here rather than reach a client.
     */
    @Test
    void adminModeAnswersExactly() throws Exception {
        URI mode = URI.create("http://localhost:" + port + "/admin/mode");
        try (HttpClient http = TestHttp.newClient()) {
            HttpResponse<String> refused = http.send(TestHttp.request(mode).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> read = http.send(TestHttp.request(mode).header("X-Admin-Token", ADMIN_TOKEN).GET()
                    .build(), HttpResponse.BodyHandlers.ofString());

            assertEquals(403, refused.statusCode());
            assertEquals("{\"error\":\"admin token required\"}", refused.body());
            assertEquals("application/json", refused.headers().firstValue("Content-Type").orElse(null));
            assertEquals(200, read.statusCode());
            assertEquals("{\"mode\":\"ENFORCE\"}", read.body());
            assertEquals("application/json", read.headers().firstValue("Content-Type").orElse(null));
        }
    }
}
