// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.async.DeferredResult;

/**
 * Responses, end to end through the real servlet container and the real RestClient: the filter attests what the
 * handler sent, and the caller's interceptor verifies it and records what it learnt as influence. Whatever the
 * caller cannot verify still counts, as one {@code local-untrusted} entry, because dropping it would let content
 * shape later calls unseen. The app is named {@code localhost} and calls itself, as in {@link MeshRoundTripTest}.
 */
@SpringBootTest(classes = ResponseAttestationTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "spring.main.banner-mode=off")
class ResponseAttestationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-response");
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
    @Import(Handlers.class)
    static class App {
    }

    @RestController
    static class Handlers {
        @GetMapping("/labelled")
        String labelled() {
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
            return "alice's order history";
        }

        @GetMapping("/no-content")
        ResponseEntity<Void> noContent() {
            return ResponseEntity.noContent().build();
        }

        @GetMapping("/empty")
        String empty() {
            return "";
        }

        @GetMapping("/sized")
        void sized(HttpServletResponse response) throws IOException {
            byte[] body = "sized".getBytes(StandardCharsets.UTF_8);
            response.setHeader("Content-Length", String.valueOf(body.length));
            response.getOutputStream().write(body);
        }

        @GetMapping("/deferred")
        DeferredResult<String> deferred() {
            DeferredResult<String> result = new DeferredResult<>();
            Thread.ofVirtual().start(() -> result.setResult("finished later on another thread"));
            return result;
        }

        @GetMapping("/callable")
        Callable<String> callable() {
            return () -> "finished later on another thread";
        }

        /** Under {@code /debug}, so the filter skips it and nothing attests it. */
        @GetMapping("/debug/plain")
        String plain() {
            return "plain";
        }

        /** Unattested, with an attestation header of its own that is not one. */
        @GetMapping("/debug/garbage")
        String garbage(HttpServletResponse response) {
            response.setHeader(PaztportHeaders.RESPONSE, "garbage");
            return "garbage";
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

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    /**
     * Calls {@code path} with the app's stamping client, inside a context scope as a request handler would be,
     * and answers the status, the body and what the call recorded, whatever they are.
     */
    private Answer call(RestClient client, String path) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            return client.get().uri(uri(path)).exchange((request, response) -> new Answer(
                    response.getStatusCode().value(), response.getBody().readAllBytes(),
                    response.getHeaders().getFirst(PaztportHeaders.RESPONSE), PaztportContext.influence()), false);
        }
    }

    /** {@code recorded} is read after the interceptor returns, so it holds what this call added. */
    private record Answer(int status, byte[] body, String attestation, List<InfluenceEntry> recorded) {
    }

    private static InfluenceEntry untrusted(Answer answer) {
        return new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:localhost",
                HttpV3.resultHash(answer.status(), answer.body()), null, null);
    }

    private List<String> responseTraces() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(l -> l.startsWith("PAZTPORT_TRACE response ")).toList();
    }

    @Test
    void labelsCarried() {
        Answer answer = call(builder.build(), "/labelled");

        assertEquals(200, answer.status());
        assertEquals("alice's order history", new String(answer.body(), StandardCharsets.UTF_8));
        List<InfluenceEntry> influence = answer.recorded();
        assertEquals(1, influence.size(), influence.toString());
        InfluenceEntry entry = influence.get(0);
        assertEquals(InfluenceClass.PRIVATE, entry.cls());
        assertEquals("alice", entry.owner());
        assertEquals("http:localhost", entry.src());
        assertEquals(HttpV3.resultHash(200, answer.body()), entry.h());
        assertFalse(entry.cid() == null || entry.cid().isEmpty(), "the label's content id travels with it");
        assertEquals(1, responseTraces().size());
        assertTrue(responseTraces().get(0).matches(
                "PAZTPORT_TRACE response rid=\\S+ from=localhost reason=OK receiver=localhost ✓ labels=private"),
                responseTraces().get(0));
    }

    @Test
    void emptyAnd204Verify() {
        RestClient client = builder.build();
        Answer noContent = call(client, "/no-content");
        Answer empty = call(client, "/empty");
        Answer sized = call(client, "/sized");

        assertEquals(204, noContent.status());
        assertEquals(0, noContent.body().length);
        assertEquals(200, empty.status());
        assertEquals(0, empty.body().length);
        assertEquals("sized", new String(sized.body(), StandardCharsets.UTF_8));
        List<String> lines = responseTraces();
        assertEquals(3, lines.size(), lines.toString());
        for (String line : lines) {
            assertTrue(line.contains(" reason=OK receiver=localhost ✓ labels=-"), line);
        }
        for (Answer answer : List.of(noContent, empty, sized)) {
            assertEquals(List.of(), answer.recorded(), "verified, unlabelled and so nothing to record");
        }
    }

    @Test
    void plainDownstreamIsUntrusted() {
        RestClient client = builder.build();

        Answer plain = call(client, "/debug/plain");
        assertEquals("plain", new String(plain.body(), StandardCharsets.UTF_8));
        assertNull(plain.attestation());
        assertEquals(List.of(untrusted(plain)), plain.recorded());

        Answer garbage = call(client, "/debug/garbage");
        assertEquals("garbage", new String(garbage.body(), StandardCharsets.UTF_8));
        assertEquals("garbage", garbage.attestation());
        assertEquals(List.of(untrusted(garbage)), garbage.recorded());

        List<String> lines = responseTraces();
        assertEquals(2, lines.size(), lines.toString());
        for (String line : lines) {
            assertTrue(line.contains(" reason=CHAIN_MISSING receiver=localhost ✗ labels=-"), line);
        }
    }

    @Test
    void refusalIsUntrusted() {
        // Runs after the stamping interceptor and claims influence the stamp never committed to, so the
        // verifying filter refuses the request.
        RestClient client = builder.clone().requestInterceptor((request, body, execution) -> {
            request.getHeaders().set(PaztportHeaders.INFLUENCE, HttpV3.encodeInfluence(List.of(
                    new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null))));
            return execution.execute(request, body);
        }).build();

        Answer refused = call(client, "/labelled");

        assertEquals(403, refused.status());
        assertTrue(new String(refused.body(), StandardCharsets.UTF_8).contains("INFLUENCE_MISMATCH"));
        assertNull(refused.attestation(), "a refusal is not attested");
        assertEquals(List.of(untrusted(refused)), refused.recorded());
    }

    @Test
    void asyncIsServedWholeButUnattested() {
        RestClient client = builder.build();
        for (String path : List.of("/deferred", "/callable")) {
            Answer answer = call(client, path);

            assertEquals(200, answer.status(), path);
            assertEquals("finished later on another thread", new String(answer.body(), StandardCharsets.UTF_8),
                    path + ": the body written after the filter returned still reaches the caller");
            assertNull(answer.attestation(), path + ": the filter had returned before the body existed");
            assertEquals(List.of(untrusted(answer)), answer.recorded(), path);
        }
    }
}
