// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
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
import org.paztport.core.ReplyCheck;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.http.HttpSessions;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

/**
 * The partner's handshake through the real container under mutual TLS. The app is the partner's entry, serving the
 * fixture {@code payment} certificate; the clients are other fixture services, so the peer a session belongs to is
 * the certificate's service. The startup refusals are checked in a context of their own.
 */
@SpringBootTest(classes = PartnerHandshakeTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "server.ssl.bundle=psp",
            "server.ssl.client-auth=need",
            "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key",
            "spring.ssl.bundle.pem.psp.truststore.certificate=classpath:tls/ca.crt"})
class PartnerHandshakeTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair SHOP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair SHOP_POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_POLICY = Crypto.generateEd25519KeyPair();
    private static final String SHOP_PIN = pub(SHOP_POLICY);
    private static final String PSP_PIN = pub(PSP_POLICY);
    private static final KeyringFile SHOP_RING =
            KeyringFile.sign(Map.of("payment", pub(SHOP_KEY)), SHOP_PIN, SHOP_POLICY.getPrivate());
    private static Path trust;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-partner");
        Files.writeString(trust.resolve("policy.pub"), PSP_PIN + "\n");
        Files.writeString(trust.resolve("policy.key"), Base64Url.encode(Crypto.encodePrivateKey(PSP_POLICY.getPrivate())));
        Files.writeString(trust.resolve("other.key"),
                Base64Url.encode(Crypto.encodePrivateKey(Crypto.generateEd25519KeyPair().getPrivate())));
        Files.writeString(trust.resolve("shop-policy.pub"), SHOP_PIN + "\n");
        JSON.writeValue(trust.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("psp", pub(PSP_KEY)), PSP_PIN, PSP_POLICY.getPrivate()));
        JSON.writeValue(trust.resolve("root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, PSP_POLICY.getPrivate()).signedRoot());

        registry.add("paztport.service-name", () -> "psp");
        registry.add("paztport.keyring-path", () -> trust.resolve("keyring.json").toString());
        registry.add("paztport.root-path", () -> trust.resolve("root.json").toString());
        registry.add("paztport.policy-key-path", () -> trust.resolve("policy.pub").toString());
        registry.add("paztport.partner.enabled", () -> "true");
        registry.add("paztport.partner.policy-private-key-path", () -> trust.resolve("policy.key").toString());
        registry.add("paztport.partner.client-policy-key-paths[0]", () -> trust.resolve("shop-policy.pub").toString());
        registry.add("paztport.partner.client-origins[0]", () -> "payment");
        registry.add("paztport.partner.unsafe-disabled[0]", () -> "POST /refund");
    }

    @AfterAll
    static void removeTrustFiles() throws IOException {
        POOLED.forEach(PooledTlsClient::close);
        try (Stream<Path> files = Files.walk(trust)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class App {
    }

    @LocalServerPort
    private int port;

    @Autowired
    private PartnerSessions sessions;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger trace = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

    @BeforeEach
    void watch() {
        logs.start();
        trace.addAppender(logs);
        trace.setLevel(Level.INFO);
        trace.setAdditive(false);
    }

    @AfterEach
    void stopWatching() {
        trace.detachAppender(logs);
        trace.setLevel(null);
        trace.setAdditive(true);
    }

    private static final List<PooledTlsClient> POOLED = new CopyOnWriteArrayList<>();

    /** A pooled client presenting the fixture certificate {@code name} and trusting the shop's CA. */
    private static RestClient client(String name) {
        PooledTlsClient pooled = PooledTlsClient.of(SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))));
        POOLED.add(pooled);
        return pooled.builder().build();
    }

    private record Answer(int status, String body) {
    }

    private Answer post(RestClient client, byte[] body) {
        return client.post()
                .uri("https://localhost:" + port + HttpSessions.PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                        new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }

    private static SessionRequest request(String nonce) {
        return new SessionRequest(
                PolicyBuilder.build(List.of(List.of("payment", "x")), 4, SHOP_POLICY.getPrivate()).signedRoot(),
                SHOP_PIN, SHOP_RING.services(), SHOP_RING.sig(), nonce);
    }

    private static byte[] json(SessionRequest req) throws IOException {
        return JSON.writeValueAsBytes(req.toJson());
    }

    @Test
    void handshakeOverHttp() throws Exception {
        SessionRequest req = request(Sessions.newNonce());

        Answer answer = post(client("orders"), json(req));

        assertEquals(200, answer.status());
        JsonNode reply = JSON.readTree(answer.body());
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(reply, req, PSP_PIN));
        assertNotNull(sessions.find("orders", reply.get("sess").asText()));
        assertThat(logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList())
                .contains("PAZTPORT_TRACE session peer=orders status=attested");
    }

    @Test
    void sessionBelongsToTheCertificatesService() throws Exception {
        String sess = JSON.readTree(post(client("orders"), json(request(Sessions.newNonce()))).body())
                .get("sess").asText();

        assertNotNull(sessions.find("orders", sess));
        assertNull(sessions.find("gateway", sess));
    }

    @Test
    void badBodyInvalidParams() {
        Answer answer = post(client("orders"), "{}".getBytes(StandardCharsets.UTF_8));

        assertEquals(new Answer(400, "{\"error\":\"INVALID_PARAMS\"}"), answer);
    }

    @Test
    void shortNonceNoSession() throws Exception {
        String shortNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[15]);

        Answer answer = post(client("operator"), json(request(shortNonce)));

        assertEquals(new Answer(400, "{\"error\":\"NO_SESSION\"}"), answer);
    }

    private static ApplicationContextRunner bare() {
        return new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PaztportAutoConfiguration.class))
            .withPropertyValues(
                    "paztport.service-name=psp",
                    "paztport.keyring-path=" + trust.resolve("keyring.json"),
                    "paztport.root-path=" + trust.resolve("root.json"),
                    "paztport.policy-key-path=" + trust.resolve("policy.pub"),
                    "paztport.partner.enabled=true",
                    "paztport.partner.policy-private-key-path=" + trust.resolve("policy.key"));
    }

    private static ApplicationContextRunner runner() {
        return bare().withPropertyValues(
                "paztport.partner.client-policy-key-paths[0]=" + trust.resolve("shop-policy.pub"),
                "paztport.partner.client-origins[0]=payment");
    }

    @Test
    void validConfigurationStarts() {
        runner().run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(PartnerSessions.class)
                    .hasSingleBean(FilterRegistrationBean.class);
            // The partner's filter replaces the shop's, so no request is verified twice or as a shop hop.
            assertThat(context.getBean(FilterRegistrationBean.class).getFilter()).isInstanceOf(PartnerFilter.class);
        });
    }

    @Test
    void mismatchedPrivateKeyFailsStartup() {
        runner().withPropertyValues("paztport.partner.policy-private-key-path=" + trust.resolve("other.key"))
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("does not match paztport.policy-key-path"));
    }

    @Test
    void partnerWithVerifyFailsStartup() {
        runner().withPropertyValues("paztport.verify=true")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("cannot be combined with paztport.verify=true"));
    }

    @Test
    void noClientsFailsStartup() {
        bare().withPropertyValues("paztport.partner.client-origins[0]=payment")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("paztport.partner.client-policy-key-paths"));
    }

    @Test
    void noOriginsFailsStartup() {
        bare().withPropertyValues("paztport.partner.client-policy-key-paths[0]=" + trust.resolve("shop-policy.pub"))
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("paztport.partner.client-origins"));
    }
}
