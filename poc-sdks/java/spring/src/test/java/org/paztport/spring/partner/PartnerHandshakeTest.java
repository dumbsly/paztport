// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
import java.util.ArrayList;
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
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.http.HttpSessions;
import org.paztport.http.PartnerSessions;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.PartnerFilter;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.outbound.PooledTlsClient;
import org.slf4j.LoggerFactory;
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
 * the certificate's issuer and service. It trusts the foreign CA as well as the shop's, so two peers can share a
 * service name and differ only by issuer. Each peer may hold two sessions here. The startup refusals are checked in
 * a context of their own.
 */
@SpringBootTest(classes = PartnerHandshakeTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "server.ssl.bundle=psp",
            "server.ssl.client-auth=need",
            "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key"})
class PartnerHandshakeTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KeyPair SHOP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair SHOP_POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_POLICY = Crypto.generateEd25519KeyPair();
    private static final String SHOP_PIN = pub(SHOP_POLICY);
    private static final String PSP_PIN = pub(PSP_POLICY);
    private static final KeyringFile SHOP_RING =
            KeyringFile.sign(Map.of("payment", pub(SHOP_KEY)), SHOP_PIN, NOT_AFTER, SHOP_POLICY.getPrivate());
    /** The PSP's reply certificate for its entry key, valid for a week. */
    private static final ReplyCert CERT = ReplyCert.issue(PSP_PIN, "psp", pub(PSP_KEY),
            System.currentTimeMillis() + 7 * 86_400_000L, PSP_POLICY.getPrivate());
    private static Path trust;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-partner");
        Files.writeString(trust.resolve("policy.pub"), PSP_PIN + "\n");
        Files.writeString(trust.resolve("psp.key"), Base64Url.encode(Crypto.encodePrivateKey(PSP_KEY.getPrivate())));
        Files.writeString(trust.resolve("reply-cert.json"), CERT.toJson());
        Files.writeString(trust.resolve("shop-policy.pub"), SHOP_PIN + "\n");
        JSON.writeValue(trust.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("psp", pub(PSP_KEY)), PSP_PIN, NOT_AFTER, PSP_POLICY.getPrivate()));
        JSON.writeValue(trust.resolve("root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4,
                        NOT_AFTER, PSP_POLICY.getPrivate()).signedRoot());

        // The partner trusts both CAs, so a foreign-orders certificate reaches the filter rather than the handshake.
        Path bothCas = trust.resolve("partner-trust.crt");
        Files.writeString(bothCas, fixture("ca.crt") + fixture("foreign-ca.crt"));
        registry.add("spring.ssl.bundle.pem.psp.truststore.certificate", () -> "file:" + bothCas);
        registry.add("paztport.service-name", () -> "psp");
        registry.add("paztport.keyring-path", () -> trust.resolve("keyring.json").toString());
        registry.add("paztport.root-path", () -> trust.resolve("root.json").toString());
        registry.add("paztport.policy-key-path", () -> trust.resolve("policy.pub").toString());
        registry.add("paztport.origins", () -> "gateway");
        registry.add("paztport.partner.enabled", () -> "true");
        registry.add("paztport.key-path", () -> trust.resolve("psp.key").toString());
        registry.add("paztport.partner.reply-cert-path", () -> trust.resolve("reply-cert.json").toString());
        registry.add("paztport.partner.client-policy-key-paths[0]", () -> trust.resolve("shop-policy.pub").toString());
        registry.add("paztport.partner.client-origins[0]", () -> "payment");
        registry.add("paztport.partner.unsafe-disabled[0]", () -> "POST /refund");
        registry.add("paztport.partner.max-sessions-per-peer", () -> "2");
    }

    private static String fixture(String name) throws IOException {
        try (var in = PartnerHandshakeTest.class.getResourceAsStream("/tls/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        }
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
        return SessionRequest.of(
                PolicyBuilder.build(List.of(List.of("payment", "x")), 4,
                        NOT_AFTER, SHOP_POLICY.getPrivate()).signedRoot(),
                SHOP_PIN, SHOP_RING, nonce);
    }

    private static byte[] json(SessionRequest req) throws IOException {
        return req.toJson().getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void handshakeOverHttp() throws Exception {
        SessionRequest req = request(Sessions.newNonce());

        Answer answer = post(client("orders"), json(req));

        assertEquals(200, answer.status());
        SessionReply reply = SessionReply.parse(answer.body());
        assertEquals(reply.toJson(), answer.body(), "the reply exactly as the SDK writes it");
        assertEquals(ReplyCheck.ATTESTED,
                Sessions.checkReply(answer.body(), req, PSP_PIN, "psp", System.currentTimeMillis()));
        assertOpen("orders", reply.sess());
        assertThat(logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList())
                .contains("PAZTPORT_TRACE session peer=orders status=attested");
    }

    /**
     * Material on both sides: the request carries the shop keyring's window and its root's, the partner
     * keeps them, so its session is attested, and the reply carries the partner keyring's window and its root's, so
     * the client's check attests it too. A side that dropped a window would fail the other's signature check.
     */
    @Test
    void materialOnBothSidesIsAttested() throws Exception {
        SessionRequest req = request(Sessions.newNonce());
        assertEquals(NOT_AFTER, JSON.readTree(req.toJson()).get("clientKeyringNotAfter").longValue());
        assertEquals(NOT_AFTER, JSON.readTree(req.toJson()).get("clientRoot").get("notAfter").longValue());

        String body = post(client("orders"), json(req)).body();
        JsonNode reply = JSON.readTree(body);

        assertEquals(NOT_AFTER, reply.get("serverKeyringNotAfter").longValue());
        assertEquals(NOT_AFTER, reply.get("serverRoot").get("notAfter").longValue());
        assertEquals("attested", reply.get("status").asText());
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(body, req, PSP_PIN, "psp", System.currentTimeMillis()));
        assertOpen("orders", reply.get("sess").asText());
    }

    // Forged: the reply checked for another entry, after its certificate's notAfter, and passed off as the
    // policy-key form. Only the first check, for the entry the client configured and in time, accepts it.
    @Test
    void replySignedByServiceKey() throws Exception {
        SessionRequest req = request(Sessions.newNonce());
        String body = post(client("orders"), json(req)).body();
        JsonNode reply = JSON.readTree(body);
        long now = System.currentTimeMillis();

        assertEquals(JSON.readTree(CERT.toJson()), reply.get("serverReplyCert"));
        assertEquals(ReplyCheck.ATTESTED, Sessions.checkReply(body, req, PSP_PIN, "psp", now));
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(body, req, PSP_PIN, "ledger", now));
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(body, req, PSP_PIN, "psp", CERT.notAfter() + 1));
        SessionReply read = SessionReply.parse(body);
        SessionReply stripped = new SessionReply(read.serverRoot(), read.serverPolicyKey(), read.serverKeyring(), null,
                read.serverKeyringNotAfter(), null, read.nonce(), read.sess(), read.status(), read.disabled(),
                read.sig());
        assertEquals(ReplyCheck.BAD_SIGNATURE, Sessions.checkReply(stripped.toJson(), req, PSP_PIN, "psp", now));
    }

    @Test
    void sessionBelongsToTheCertificatesService() throws Exception {
        String sess = JSON.readTree(post(client("orders"), json(request(Sessions.newNonce()))).body())
                .get("sess").asText();

        assertOpen("orders", sess);
        assertUnknown("gateway", sess);
    }

    // Forged: a session the shop's orders opened, named by a certificate with the same name from another CA the
    // partner also trusts. The filter looks the id up under the request's own issuer, so it is unknown there.
    @Test
    void sessionUnknownToTheSameNameFromAnotherIssuer() throws Exception {
        String sess = JSON.readTree(post(client("orders"), json(request(Sessions.newNonce()))).body())
                .get("sess").asText();

        Answer foreign = call(client("foreign-orders"), sess);
        Answer own = call(client("orders"), sess);

        assertEquals(403, foreign.status());
        assertEquals("SESSION_UNKNOWN", JSON.readTree(foreign.body()).get("reason").asText());
        // The same id from the certificate that opened it is found, and fails later, on its missing chain.
        assertEquals(403, own.status());
        assertEquals("CHAIN_MISSING", JSON.readTree(own.body()).get("reason").asText());
    }

    /** A session found and attested verifies the chain, so an id with none is refused for it, not as unknown. */
    private void assertOpen(String peer, String sess) throws Exception {
        Answer answer = call(client(peer), sess);

        assertEquals(403, answer.status());
        assertEquals("CHAIN_MISSING", JSON.readTree(answer.body()).get("reason").asText());
    }

    private void assertUnknown(String peer, String sess) throws Exception {
        Answer answer = call(client(peer), sess);

        assertEquals(403, answer.status());
        assertEquals("SESSION_UNKNOWN", JSON.readTree(answer.body()).get("reason").asText());
    }

    private Answer call(RestClient client, String sess) {
        return client.post()
                .uri("https://localhost:" + port + "/anything")
                .header(PaztportHeaders.SESSION, sess)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{}")
                .exchange((request, response) -> new Answer(response.getStatusCode().value(),
                        new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }

    // Forged: an id the peer opened itself, sent after two newer handshakes of its own evicted it.
    @Test
    void sessionUnknownForEvictedId() throws Exception {
        RestClient gateway = client("gateway");
        List<String> opened = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            opened.add(JSON.readTree(post(gateway, json(request(Sessions.newNonce()))).body()).get("sess").asText());
        }

        assertUnknown("gateway", opened.get(0));
        assertOpen("gateway", opened.get(1));
        assertOpen("gateway", opened.get(2));
    }

    /** The reply and a refusal alike go out as the SDK wrote them, labelled JSON and nothing more. */
    @Test
    void sessionAnswersAreJson() throws Exception {
        for (byte[] body : List.of(json(request(Sessions.newNonce())), "{}".getBytes(StandardCharsets.UTF_8))) {
            String type = client("orders").post()
                    .uri("https://localhost:" + port + HttpSessions.PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .exchange((request, response) -> response.getHeaders().getFirst("Content-Type"));

            assertEquals("application/json", type);
        }
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
                    "paztport.origins=gateway",
                    "paztport.partner.enabled=true",
                    "paztport.key-path=" + trust.resolve("psp.key"),
                    "paztport.partner.reply-cert-path=" + trust.resolve("reply-cert.json"));
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
    void partnerWithVerifyFailsStartup() {
        runner().withPropertyValues("paztport.verify=true")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("cannot be combined with paztport.verify=true"));
    }

    @Test
    void nonPositiveLimitsFailStartup() {
        for (String property : List.of("paztport.partner.max-sessions-per-peer", "paztport.partner.session-idle-ms")) {
            runner().withPropertyValues(property + "=0")
                    .run(context -> assertThat(context).hasFailed().getFailure()
                            .hasStackTraceContaining(property));
        }
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
