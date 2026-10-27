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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
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
 * the URI host, and calls itself; its keys, signed keyring, pin and policy are generated for each run.
 */
@SpringBootTest(classes = MeshRoundTripTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.banner-mode=off")
class MeshRoundTripTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-mesh");
        KeyPair app = Crypto.generateEd25519KeyPair();
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        PolicyBuilder.Result built =
                PolicyBuilder.build(List.of(List.of("localhost", "localhost")), 4, policy.getPrivate());

        Files.writeString(trust.resolve("localhost.key"), Base64Url.encode(Crypto.encodePrivateKey(app.getPrivate())));
        Files.writeString(trust.resolve("policy.pub"), policyPub);
        JSON.writeValue(trust.resolve("keyring.json").toFile(), KeyringFile.sign(
                Map.of("localhost", Base64Url.encode(Crypto.encodePublicKey(app.getPublic()))), policyPub,
                policy.getPrivate()));
        JSON.writeValue(trust.resolve("root.json").toFile(), built.signedRoot());
        JSON.writeValue(trust.resolve("proofs-localhost.json").toFile(), built.bundles().get("localhost"));

        registry.add("paztport.service-name", () -> "localhost");
        registry.add("paztport.instance", () -> "localhost-1");
        registry.add("paztport.origin", () -> "true");
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
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({HopController.class, SearchController.class})
    static class App {
    }

    /** Calls the app's own search, through the stamping RestClient, with a percent-encoded query. */
    @RestController
    static class HopController {
        private final RestClient client;
        private final Environment env;

        HopController(RestClient.Builder builder, Environment env) {
            this.client = builder.build();
            this.env = env;
        }

        @GetMapping("/hop")
        Map<String, String> hop() {
            URI search = URI.create(
                    "http://localhost:" + env.getProperty("local.server.port") + "/search?q=caf%C3%A9%20x");
            return client.get().uri(search).retrieve().body(new ParameterizedTypeReference<>() { });
        }
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
    private RestClient.Builder builder;

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
        // The test thread is outside any request, so the origin starts a chain here too and /hop is verified first.
        Map<String, String> body = builder.build().get().uri(URI.create("http://localhost:" + port + "/hop"))
                .retrieve().body(new ParameterizedTypeReference<>() { });

        assertEquals(Map.of("q", "café x"), body);
        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(2, lines.size(), lines.toString());
        for (String line : lines) {
            assertTrue(line.contains(" reason=OK receiver=localhost ✓ peer=none "), line);
        }
    }
}
