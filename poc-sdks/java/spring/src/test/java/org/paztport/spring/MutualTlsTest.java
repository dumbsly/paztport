// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.StamperV3;
import org.paztport.core.Peer;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * The verifying receiver under mutual TLS, through the real container: the client certificate the handshake
 * authenticated is the peer, so a chain must have been signed last by the service that holds that certificate, and
 * every result names the certificate's holder at the address it connected from. A client whose certificate the
 * shop's CA did not issue never reaches the filter at all. The app is {@code payment}, serving its own fixture
 * certificate on {@code 127.0.0.1}; the chains are built here and sent over plain SSL clients.
 */
@SpringBootTest(classes = MutualTlsTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "server.address=127.0.0.1",
            "server.ssl.bundle=payment",
            "server.ssl.client-auth=need",
            "spring.ssl.bundle.pem.payment.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.payment.keystore.private-key=classpath:tls/payment.key",
            "spring.ssl.bundle.pem.payment.truststore.certificate=classpath:tls/ca.crt"})
class MutualTlsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final KeyPair GATEWAY = Crypto.generateEd25519KeyPair();
    private static final KeyPair ORDERS = Crypto.generateEd25519KeyPair();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final PolicyBuilder.Result BUILT =
            PolicyBuilder.build(List.of(List.of("gateway", "orders", "payment")), 4, POLICY.getPrivate());
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-mtls");
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(POLICY.getPublic()));
        Files.writeString(trust.resolve("policy.pub"), policyPub);
        JSON.writeValue(trust.resolve("keyring.json").toFile(), KeyringFile.sign(Map.of(
                "gateway", Base64Url.encode(Crypto.encodePublicKey(GATEWAY.getPublic())),
                "orders", Base64Url.encode(Crypto.encodePublicKey(ORDERS.getPublic()))), policyPub,
                POLICY.getPrivate()));
        JSON.writeValue(trust.resolve("root.json").toFile(), BUILT.signedRoot());

        registry.add("paztport.service-name", () -> "payment");
        registry.add("paztport.verify", () -> "true");
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
    @Import(Pay.class)
    static class App {
    }

    /** Notes the peer the request it serves was sent by, as the filter read it from the connection. */
    @RestController
    static class Pay {
        static final List<Peer> PEERS = new CopyOnWriteArrayList<>();

        @PostMapping("/pay")
        String pay(HttpServletRequest request) {
            PEERS.add(PeerIdentity.from(request));
            return "paid";
        }
    }

    @LocalServerPort
    private int port;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final List<Logger> captured = List.of(
            (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE"), (Logger) LoggerFactory.getLogger("PAZTPORT_EVENT"));

    @BeforeEach
    void watch() {
        Pay.PEERS.clear();
        logs.start();
        for (Logger log : captured) {
            log.addAppender(logs);
            log.setLevel(Level.INFO);
            log.setAdditive(false);
        }
    }

    @AfterEach
    void stopWatching() {
        for (Logger log : captured) {
            log.detachAppender(logs);
            log.setLevel(null);
            log.setAdditive(true);
        }
    }

    private List<String> lines(String prefix) {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage).filter(l -> l.startsWith(prefix)).toList();
    }

    /** A plain SSL client presenting the fixture certificate {@code name} and trusting the shop's CA: no stamping. */
    private static RestClient client(String name) {
        SslBundle bundle = SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt")));
        return RestClient.builder()
                .requestFactory(ClientHttpRequestFactories.get(
                        ClientHttpRequestFactorySettings.DEFAULTS.withSslBundle(bundle)))
                .build();
    }

    private record Answer(int status, String body) {
    }

    /** Sends a chain stamped gateway, then orders, for payment, over {@code client}. */
    private Answer sendOrdersChain(RestClient client) {
        String rid = UUID.randomUUID().toString();
        StamperV3.Stamped gw = new StamperV3("gateway", "gw-1", GATEWAY.getPrivate(), true, () -> rid,
                System::currentTimeMillis)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        BUILT.bundles().get("gateway"));
        StamperV3.Stamped ord = new StamperV3("orders", "ord-1", ORDERS.getPrivate(), false, () -> "x",
                System::currentTimeMillis)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), List.of(),
                        BUILT.bundles().get("orders"));
        return client.post()
                .uri("https://127.0.0.1:" + port + "/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .header(PaztportHeaders.CHAIN, HttpV3.encodeChain(ord.chain()))
                .header(PaztportHeaders.PROOF, HttpV3.encodeProof(ord.proof()))
                .body(TO_PAYMENT)
                .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                        new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }

    @Test
    void theChainsLastSignerPresentingItsCertificateIsAccepted() {
        Answer answer = sendOrdersChain(client("orders"));

        assertEquals(new Answer(200, "paid"), answer);
        assertEquals(List.of(new Peer("orders", "127.0.0.1")), Pay.PEERS, "the peer every result names");
        List<String> traces = lines("PAZTPORT_TRACE request ");
        assertEquals(1, traces.size(), traces.toString());
        assertTrue(traces.get(0).contains(" reason=OK receiver=payment ✓ peer=orders (mTLS) "), traces.get(0));
    }

    @Test
    void anotherServicesCertificateIsRefusedAndNamed() throws Exception {
        Answer answer = sendOrdersChain(client("gateway"));

        assertEquals(403, answer.status());
        JsonNode body = JSON.readTree(answer.body());
        assertEquals("PEER_MISMATCH", body.get("reason").asText());
        assertEquals("gateway", body.get("suspectSvc").asText());
        assertEquals("127.0.0.1", body.get("suspectInst").asText());
        assertEquals(List.of("PAZTPORT_EVENT reason=PEER_MISMATCH suspectSvc=gateway suspectInst=127.0.0.1 "),
                lines("PAZTPORT_EVENT ").stream().map(l -> l.substring(0, l.indexOf("rid="))).toList());
        List<String> traces = lines("PAZTPORT_TRACE request ");
        assertEquals(1, traces.size(), traces.toString());
        assertTrue(traces.get(0).contains(" reason=PEER_MISMATCH receiver=payment ✗ peer=gateway (mTLS) "),
                traces.get(0));
    }

    /**
     * A certificate the shop's CA issued but that names no service gives the peer the service {@code ""}. The check
     * still runs and fails, since no chain's last signer is {@code ""}; an empty name never means "skip the check".
     */
    @Test
    void aCertificateWithNoCommonNameIsRefusedNotSkipped() throws Exception {
        Answer answer = sendOrdersChain(client("nameless"));

        assertEquals(403, answer.status());
        JsonNode body = JSON.readTree(answer.body());
        assertEquals("PEER_MISMATCH", body.get("reason").asText());
        assertEquals("", body.get("suspectSvc").asText());
        assertEquals("127.0.0.1", body.get("suspectInst").asText());
        assertEquals(List.of(), Pay.PEERS, "refused before the handler");
        List<String> traces = lines("PAZTPORT_TRACE request ");
        assertEquals(1, traces.size(), traces.toString());
        assertTrue(traces.get(0).contains(" reason=PEER_MISMATCH receiver=payment ✗ peer=\"\" (mTLS) "),
                traces.get(0));
    }

    @Test
    void aRefusalThroughTheStampingClientIsAnsweredNotThrown() {
        // An SSL bundle puts RestClient on HttpURLConnection, which hands over an error body only once the status
        // has been read; the interceptor reads the whole body, so it must not reach for it first.
        RestClient stamping = client("gateway").mutate()
                .requestInterceptor(new OutboundInterceptor(new StamperV3("gateway", "gw-1", GATEWAY.getPrivate(),
                        true, () -> UUID.randomUUID().toString(), System::currentTimeMillis),
                        BUILT.bundles().get("gateway"), null, "gateway"))
                .build();

        Answer answer = stamping.post()
                .uri("https://127.0.0.1:" + port + "/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .body(TO_PAYMENT)
                .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                        new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));

        assertEquals(403, answer.status());
        assertTrue(answer.body().contains("\"reason\""), answer.body());
        assertEquals(List.of(), Pay.PEERS, "refused before the handler");
    }

    @Test
    void aCertificateFromAnotherCaFailsTheHandshake() {
        assertThrows(RestClientException.class, () -> sendOrdersChain(client("foreign-orders")));

        assertEquals(List.of(), lines("PAZTPORT_TRACE "), "the filter never ran");
        assertEquals(List.of(), Pay.PEERS);
    }
}
