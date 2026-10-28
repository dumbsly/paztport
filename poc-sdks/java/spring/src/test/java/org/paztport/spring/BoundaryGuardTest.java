// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.Crypto;
import org.paztport.core.Influence;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.StamperV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The guard through the real filter and container: {@code payment} verifies requests, and its handler sends each
 * one on to a stub partner through the boundary client. Only a chain that passed the live order here may cross; a
 * forged chain served in audit, or any chain while the hop is off, must make the handler's call fail before a byte
 * reaches the partner. The test plays the gateway that calls {@code payment}. The keys, signed keyring, pin and
 * policy, which holds the boundary route {@code payment/psp}, are generated for each run.
 */
@SpringBootTest(classes = BoundaryGuardTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key",
            "spring.ssl.bundle.pem.psp.truststore.certificate=classpath:tls/ca.crt"})
class BoundaryGuardTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final KeyPair GATEWAY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PAYMENT = Crypto.generateEd25519KeyPair();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final PolicyBuilder.Result BUILT = PolicyBuilder.build(
            List.of(List.of("gateway", "payment"), List.of("payment", "psp")), 4, POLICY.getPrivate());
    private static Path trust;
    private static StubPartner partner;
    /** Every list the egress reported sending, through the listener bean. */
    private static final List<List<String>> SENT = new CopyOnWriteArrayList<>();

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-boundary");
        partner = new StubPartner(true);
        writeTrust(trust, partner);

        registry.add("paztport.service-name", () -> "payment");
        registry.add("paztport.instance", () -> "payment-1");
        registry.add("paztport.verify", () -> "true");
        registry.add("paztport.mode", () -> "audit");
        for (String p : allProperties(trust, partner)) {
            String[] kv = p.split("=", 2);
            registry.add(kv[0], () -> kv[1]);
        }
    }

    private static void writeTrust(Path dir, StubPartner stub) throws IOException {
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(POLICY.getPublic()));
        Files.writeString(dir.resolve("payment.key"),
                Base64Url.encode(Crypto.encodePrivateKey(PAYMENT.getPrivate())));
        Files.writeString(dir.resolve("policy.pub"), policyPub);
        Files.writeString(dir.resolve("psp-policy.pub"), stub.policyKey() + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(), KeyringFile.sign(Map.of(
                "gateway", Base64Url.encode(Crypto.encodePublicKey(GATEWAY.getPublic())),
                "payment", Base64Url.encode(Crypto.encodePublicKey(PAYMENT.getPublic()))), policyPub,
                POLICY.getPrivate()));
        JSON.writeValue(dir.resolve("root.json").toFile(), BUILT.signedRoot());
        JSON.writeValue(dir.resolve("proofs-payment.json").toFile(), BUILT.bundles().get("payment"));
        Files.writeString(dir.resolve("boundary.key"),
                Base64Url.encode(new SecureRandom().generateSeed(BoundaryInfluence.KEY_LENGTH)) + "\n");
    }

    /** Every property the boundary client needs, as {@code name=value}. */
    private static List<String> allProperties(Path dir, StubPartner stub) {
        return List.of(
                "paztport.key-path=" + dir.resolve("payment.key"),
                "paztport.proofs-path=" + dir.resolve("proofs-payment.json"),
                "paztport.keyring-path=" + dir.resolve("keyring.json"),
                "paztport.root-path=" + dir.resolve("root.json"),
                "paztport.policy-key-path=" + dir.resolve("policy.pub"),
                "paztport.boundary.partner=psp",
                "paztport.boundary.url=" + stub.url(),
                "paztport.boundary.tls-bundle=psp",
                "paztport.boundary.partner-policy-key-path=" + dir.resolve("psp-policy.pub"),
                "paztport.boundary.blinding-key-path=" + dir.resolve("boundary.key"));
    }

    @AfterAll
    static void removeTrustFiles() throws IOException {
        partner.close();
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(PayController.class)
    static class App {

        /** Records the sent list of each call, as a store of openings would keep its originals. */
        @Bean
        BoundaryListener recordingListener() {
            return (rid, partnerEntry, originals, sent) -> SENT.add(sent.stream().map(e -> e.src()).toList());
        }
    }

    /** Sends what it is given on to the partner, and relays the answer. */
    @RestController
    static class PayController {
        private final BoundaryClient boundary;

        PayController(BoundaryClient boundary) {
            this.boundary = boundary;
        }

        @PostMapping("/pay")
        ResponseEntity<byte[]> pay(@RequestBody byte[] body) {
            BoundaryClient.Response r = boundary.post("/charge", body);
            return ResponseEntity.status(r.status()).body(r.body());
        }
    }

    @LocalServerPort
    private int port;

    @Autowired
    private ModeHolder mode;

    @AfterEach
    void restoreMode() {
        mode.set(VerificationMode.AUDIT);
    }

    /** POSTs {@code /pay} as the gateway would, with a one-stamp chain signed by {@code key}. */
    private HttpResponse<byte[]> pay(KeyPair key) throws Exception {
        String rid = UUID.randomUUID().toString();
        StamperV3.Stamped stamped = new StamperV3("gateway", "gw-1", key.getPrivate(), true, () -> rid,
                System::currentTimeMillis).next(null, "payment", RequestBinding.compute("POST", "/pay", BODY),
                        List.of(), BUILT.bundles().get("gateway"));
        HttpRequest.Builder request = TestHttp.request(URI.create("http://localhost:" + port + "/pay"))
                .header("Content-Type", "application/json")
                .header(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()))
                .POST(HttpRequest.BodyPublishers.ofByteArray(BODY));
        if (stamped.proof() != null) {
            request.header(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
        }
        try (HttpClient http = TestHttp.newClient()) {
            return http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        }
    }

    @Test
    void forgedChainGetsNoBoundaryStamp() throws Exception {
        int before = partner.received().size();

        // Signed by a key outside the keyring: audit serves it, but it did not verify here.
        HttpResponse<byte[]> response = pay(Crypto.generateEd25519KeyPair());

        assertEquals(500, response.statusCode());
        assertEquals(before, partner.received().size(), "nothing reaches the partner, not even a handshake");
    }

    @Test
    void offModeGetsNoBoundaryStamp() throws Exception {
        mode.set(VerificationMode.OFF);
        int before = partner.received().size();

        HttpResponse<byte[]> response = pay(GATEWAY);

        assertEquals(500, response.statusCode());
        assertEquals(before, partner.received().size(), "nothing reaches the partner, not even a handshake");
    }

    @Test
    void enforceValidChainCrosses() throws Exception {
        mode.set(VerificationMode.ENFORCE);
        int before = partner.calls().size();

        HttpResponse<byte[]> response = pay(GATEWAY);

        assertEquals(200, response.statusCode());
        List<StubPartner.Received> calls = partner.calls();
        assertEquals(before + 1, calls.size());
        StubPartner.Received call = calls.get(calls.size() - 1);
        JsonNode chain = HttpV3.decodeChain(call.header(PaztportHeaders.CHAIN));
        assertEquals(1, chain.size());
        assertEquals("payment", chain.get(0).get("svc").textValue());
        assertEquals("psp", chain.get(0).get("rcv").textValue());
        assertEquals(call.header(PaztportHeaders.SESSION), chain.get(0).get("sess").textValue());
        assertThat(call.header(PaztportHeaders.PROOF)).isNotNull();
        // The auto-configured client reports to the listener bean what it sent.
        assertThat(SENT).isNotEmpty();
        assertEquals(Influence.parse(HttpV3.decodeInfluence(call.header(PaztportHeaders.INFLUENCE))).stream()
                .map(e -> e.src()).toList(), SENT.get(SENT.size() - 1));
    }

    // --- Startup ---

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SslAutoConfiguration.class, PaztportAutoConfiguration.class))
            .withPropertyValues(
                    "paztport.service-name=payment",
                    "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
                    "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key",
                    "spring.ssl.bundle.pem.psp.truststore.certificate=classpath:tls/ca.crt");

    private ApplicationContextRunner without(String name) {
        return runner.withPropertyValues(allProperties(trust, partner).stream()
                .filter(p -> !p.startsWith(name + "=")).toArray(String[]::new));
    }

    @Test
    void missingConfigFailsStartup() {
        without("paztport.proofs-path").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("paztport.proofs-path");
        });
        for (String name : List.of("paztport.key-path", "paztport.keyring-path", "paztport.root-path",
                "paztport.policy-key-path", "paztport.boundary.partner", "paztport.boundary.tls-bundle",
                "paztport.boundary.partner-policy-key-path", "paztport.boundary.blinding-key-path")) {
            without(name).run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).rootCause().hasMessageContaining(name);
            });
        }
    }

    // The egress sends the boundary stamp and the influence's owners, so a partner URL that is not https fails
    // the startup rather than send them in the clear.
    @Test
    void plainHttpUrlFailsStartup() {
        runner.withPropertyValues(allProperties(trust, partner).stream()
                .map(p -> p.startsWith("paztport.boundary.url=") ? p.replace("https://", "http://") : p)
                .toArray(String[]::new)).run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("paztport.boundary.url").hasMessageContaining("https");
                });
    }

    // The key keys every salt; one of another length would be stretched or cut by the MAC, so it is refused.
    @Test
    void blindingKeyOfWrongLengthFailsStartup() throws IOException {
        for (String text : List.of(Base64Url.encode(new byte[31]), Base64Url.encode(new byte[33]), "not base64!",
                "")) {
            Path bad = Files.writeString(trust.resolve("bad-boundary.key"), text);
            runner.withPropertyValues(allProperties(trust, partner).toArray(String[]::new))
                    .withPropertyValues("paztport.boundary.blinding-key-path=" + bad).run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).rootCause()
                                .hasMessageContaining("paztport.boundary.blinding-key-path")
                                .hasMessageContaining("32 bytes");
                    });
        }
    }

    @Test
    void nonPositiveIdlePeriodFailsStartup() {
        runner.withPropertyValues(allProperties(trust, partner).toArray(String[]::new))
                .withPropertyValues("paztport.boundary.session-idle-ms=0").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("paztport.boundary.session-idle-ms");
                });
    }

    @Test
    void fullConfigStartsWithItsOwnTlsClient() {
        // No paztport.tls-bundle: there is no shared client, so the boundary's must be its own.
        runner.withPropertyValues(allProperties(trust, partner).toArray(String[]::new)).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(BoundaryClient.class);
            assertThat(context).doesNotHaveBean(PooledTlsClient.class);
        });
    }

    // The egress takes one listener: two with none primary fail the startup rather than one being picked at
    // random, and marking one primary says which is told.
    @Test
    void twoListenersFailStartupUnlessOneIsPrimary() {
        BoundaryListener quiet = (rid, entry, originals, sent) -> { };
        ApplicationContextRunner two = runner.withPropertyValues(allProperties(trust, partner).toArray(String[]::new))
                .withBean("firstListener", BoundaryListener.class, () -> quiet)
                .withBean("secondListener", BoundaryListener.class, () -> quiet);
        two.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().isInstanceOf(NoUniqueBeanDefinitionException.class);
        });
        runner.withPropertyValues(allProperties(trust, partner).toArray(String[]::new))
                .withBean("firstListener", BoundaryListener.class, () -> quiet, bd -> bd.setPrimary(true))
                .withBean("secondListener", BoundaryListener.class, () -> quiet)
                .run(context -> assertThat(context).hasNotFailed().hasSingleBean(BoundaryClient.class));
    }

    @Test
    void noBoundaryUrlNoClient() {
        without("paztport.boundary.url").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(BoundaryClient.class);
        });
    }
}
