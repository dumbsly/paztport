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
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.Peer;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.spring.internal.PeerIdentity;
import org.paztport.spring.outbound.OutboundInterceptor;
import org.paztport.spring.outbound.PooledTlsClient;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
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
            "spring.ssl.bundle.pem.payment.truststore.certificate=classpath:tls/ca.crt",
            "spring.ssl.bundle.pem.orders.keystore.certificate=classpath:tls/orders.crt",
            "spring.ssl.bundle.pem.orders.keystore.private-key=classpath:tls/orders.key",
            "spring.ssl.bundle.pem.orders.truststore.certificate=classpath:tls/ca.crt",
            "paztport.tls-bundle=orders"})
class MutualTlsTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final KeyPair GATEWAY = Crypto.generateEd25519KeyPair();
    private static final KeyPair ORDERS = Crypto.generateEd25519KeyPair();
    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final PolicyBuilder.Result BUILT =
            PolicyBuilder.build(List.of(List.of("gateway", "orders", "payment")), 4, NOT_AFTER, POLICY.getPrivate());
    private static Path trust;

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-mtls");
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(POLICY.getPublic()));
        Files.writeString(trust.resolve("policy.pub"), policyPub);
        JSON.writeValue(trust.resolve("keyring.json").toFile(), KeyringFile.sign(Map.of(
                "gateway", Base64Url.encode(Crypto.encodePublicKey(GATEWAY.getPublic())),
                "orders", Base64Url.encode(Crypto.encodePublicKey(ORDERS.getPublic()))), policyPub, NOT_AFTER,
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

    /**
     * Notes the peer the request it serves was sent by, as the filter read it from the connection, and the port
     * that connection came from.
     */
    @RestController
    static class Pay {
        static final List<Peer> PEERS = new CopyOnWriteArrayList<>();
        static final List<Integer> PORTS = new CopyOnWriteArrayList<>();

        @PostMapping("/pay")
        String pay(HttpServletRequest request) {
            PEERS.add(PeerIdentity.from(request));
            PORTS.add(request.getRemotePort());
            return "paid";
        }
    }

    @LocalServerPort
    private int port;

    /**
     * The application's shared builder, which the starter gives the {@code paztport.tls-bundle} named here,
     * orders' certificate, so this app can call its own {@code /pay} as orders through the starter's client.
     */
    @Autowired
    private RestClient.Builder shared;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final List<Logger> captured = List.of(
            (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE"), (Logger) LoggerFactory.getLogger("PAZTPORT_EVENT"));

    @BeforeEach
    void watch() {
        Pay.PEERS.clear();
        Pay.PORTS.clear();
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

    /** The fixture certificate {@code name} and the shop's CA. */
    private static SslBundle fixture(String name) {
        return SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt")));
    }

    /**
     * A plain SSL client presenting the fixture certificate {@code name} and trusting the shop's CA: no stamping.
     * It is the starter's pooled client, the one every service's calls go out on.
     */
    private static RestClient client(String name) {
        PooledTlsClient pooled = PooledTlsClient.of(fixture(name));
        POOLED.add(pooled);
        return pooled.builder().build();
    }

    /** The pooled clients the tests made, closed once they have all run. */
    private static final List<PooledTlsClient> POOLED = new CopyOnWriteArrayList<>();

    @AfterAll
    static void closeClients() {
        POOLED.forEach(PooledTlsClient::close);
    }

    /**
     * As {@link #client}, but over {@code HttpURLConnection}, the client Spring Boot builds for an SSL bundle when an
     * application asks for its simple one. Its reads block without heeding an interrupt, so only its own timeouts can
     * end a stalled call.
     */
    private static RestClient urlConnectionClient(String name) {
        return RestClient.builder()
                .requestFactory(ClientHttpRequestFactoryBuilder.simple().build(
                        HttpClientSettings.ofSslBundle(fixture(name))
                                .withConnectTimeout(TestHttp.REQUEST_TIMEOUT)
                                .withReadTimeout(TestHttp.REQUEST_TIMEOUT)))
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

    /**
     * A refusal comes back with a body, which the interceptor reads whole before the caller sees it; the caller
     * must get the 403 and that body, not an exception, whichever client carried it. {@code HttpURLConnection}
     * hands over an error body only once the status has been read, so the interceptor must not reach for it first.
     */
    @Test
    void aRefusalThroughTheStampingClientIsAnsweredNotThrown() {
        for (RestClient client : List.of(client("gateway"), urlConnectionClient("gateway"))) {
            RestClient stamping = client.mutate()
                    .requestInterceptor(new OutboundInterceptor(new StamperV3("gateway", "gw-1",
                            GATEWAY.getPrivate(), true, () -> UUID.randomUUID().toString(), System::currentTimeMillis),
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
    }

    /**
     * The starter's client keeps its connections: one client's sequential calls share a pooled connection, rather
     * than each opening a fresh mutual-TLS connection that the server then holds open until its keep-alive runs
     * out, which once let a busy mesh reach the server's connection limit and freeze. A TCP connection is the
     * client's address and port, and no port is reused while its connection is open, so the distinct ports the
     * server saw count the connections; a client that never reuses one leaves all of them open, one per call.
     */
    @Test
    void theStartersClientReusesItsConnections() {
        RestClient client = shared.build();
        int calls = 50;
        for (int i = 0; i < calls; i++) {
            assertEquals(new Answer(200, "paid"), sendOrdersChain(client));
        }

        assertEquals(calls, Pay.PORTS.size());
        long connections = Pay.PORTS.stream().distinct().count();
        assertTrue(connections <= 2, connections + " connections for " + calls + " sequential calls");
    }

    @Test
    void aCertificateFromAnotherCaFailsTheHandshake() {
        assertThrows(RestClientException.class, () -> sendOrdersChain(client("foreign-orders")));

        assertEquals(List.of(), lines("PAZTPORT_TRACE "), "the filter never ran");
        assertEquals(List.of(), Pay.PEERS);
    }
}
