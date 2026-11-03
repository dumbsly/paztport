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
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.ContextAccess;
import org.paztport.http.HttpSessions;
import org.paztport.http.PartnerSessions;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.PartnerFilter;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.outbound.PooledTlsClient;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * What the partner does as time passes, through the real container under mutual TLS, with a clock the test moves:
 * the partner's sessions are built as the auto-configuration builds them, by the package's factory, given that
 * clock in place of the system clock, and the filter, gate and handshake endpoint are the auto-configuration's own.
 * Its own root and keyring last three days; the shop's last one day or a month, as each test needs. A handshake
 * judged after the shop's material has lapsed opens an unsafe session, and one whose material has no {@code notAfter}
 * is answered {@code 400 INVALID_PARAMS}; a session attested while it was current is refused {@code POLICY_EXPIRED}
 * once the earlier of its client's two windows has passed; and when the partner's own material lapses it carries on,
 * opening only unsafe sessions, and says so once.
 */
@SpringBootTest(classes = PartnerLifetimeTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "server.ssl.bundle=psp",
            "server.ssl.client-auth=need",
            "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key",
            "spring.ssl.bundle.pem.psp.truststore.certificate=classpath:tls/ca.crt"})
class PartnerLifetimeTest {

    private static final long DAY_MS = 86_400_000L;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PARTNER = "localhost";
    private static final KeyPair SHOP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair SHOP_POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair GATEWAY_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_POLICY = Crypto.generateEd25519KeyPair();
    private static final String SHOP_PIN = pub(SHOP_POLICY);
    private static final String PSP_PIN = pub(PSP_POLICY);
    private static final byte[] REFUND = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final List<InfluenceEntry> INFLUENCE = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-ticket", "cid-1", null));
    /** When the test started: the partner's own material is dated from here, and the clock is moved from here. */
    private static final long START = System.currentTimeMillis();
    private static Path trust;

    /** A clock that runs from the real time at {@link #START} and is moved forward by hand. */
    static final class MovableClock {
        private final AtomicLong now = new AtomicLong(START);

        void moveTo(long millis) {
            now.set(millis);
        }

        long millis() {
            return now.get();
        }
    }

    private static final MovableClock CLOCK = new MovableClock();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-partner-lifetime");
        long ownNotAfter = START + 3 * DAY_MS;
        Files.writeString(trust.resolve("policy.pub"), PSP_PIN + "\n");
        Files.writeString(trust.resolve("entry.key"), Base64Url.encode(Crypto.encodePrivateKey(PSP_KEY.getPrivate())));
        Files.writeString(trust.resolve("shop-policy.pub"), SHOP_PIN + "\n");
        JSON.writeValue(trust.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of(PARTNER, pub(PSP_KEY)), PSP_PIN, ownNotAfter, PSP_POLICY.getPrivate()));
        Files.writeString(trust.resolve("reply-cert.json"), ReplyCert.issue(PSP_PIN, PARTNER, pub(PSP_KEY),
                START + 60 * DAY_MS, PSP_POLICY.getPrivate()).toJson());
        JSON.writeValue(trust.resolve("root.json").toFile(), PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4,
                ownNotAfter, PSP_POLICY.getPrivate()).signedRoot());

        registry.add("paztport.service-name", () -> PARTNER);
        registry.add("paztport.keyring-path", () -> trust.resolve("keyring.json").toString());
        registry.add("paztport.root-path", () -> trust.resolve("root.json").toString());
        registry.add("paztport.policy-key-path", () -> trust.resolve("policy.pub").toString());
        registry.add("paztport.partner.enabled", () -> "true");
        registry.add("paztport.key-path", () -> trust.resolve("entry.key").toString());
        registry.add("paztport.partner.reply-cert-path", () -> trust.resolve("reply-cert.json").toString());
        registry.add("paztport.partner.client-policy-key-paths[0]", () -> trust.resolve("shop-policy.pub").toString());
        registry.add("paztport.partner.client-origins[0]", () -> "orders");
        registry.add("paztport.partner.unsafe-disabled[0]", () -> "POST /refund");
        // Sessions are aged by the moved clock too, so one that must survive two days is kept for sixty.
        registry.add("paztport.partner.session-idle-ms", () -> Long.toString(60 * DAY_MS));
        registry.add("paztport.max-age-ms", () -> Long.toString(DAY_MS));
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
    @Import(Handlers.class)
    static class App {
        /** Takes the place of the auto-configured sessions, which judge by the system clock. */
        @Bean
        PartnerSessions movableClockPartnerSessions(PaztportProperties props) {
            return PartnerConfiguration.partnerSessions(props, CLOCK::millis);
        }
    }

    @RestController
    static class Handlers {
        @PostMapping("/refund")
        Map<String, Object> refund(HttpServletRequest request) {
            return seen(request);
        }

        @GetMapping("/statement")
        Map<String, Object> statement(HttpServletRequest request) {
            return seen(request);
        }

        private static Map<String, Object> seen(HttpServletRequest request) {
            Map<String, Object> seen = new LinkedHashMap<>();
            seen.put("session", request.getAttribute(PartnerFilter.SESSION_STATUS));
            return seen;
        }
    }

    @LocalServerPort
    private int port;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger partnerLog = (Logger) LoggerFactory.getLogger(PartnerSessions.class);

    @BeforeEach
    void watch() {
        CLOCK.moveTo(START);
        logs.start();
        partnerLog.addAppender(logs);
        partnerLog.setLevel(Level.WARN);
    }

    @AfterEach
    void stopWatching() {
        CLOCK.moveTo(START);
        partnerLog.detachAppender(logs);
        partnerLog.setLevel(null);
        ContextAccess.reset();
    }

    private static final List<PooledTlsClient> POOLED = new CopyOnWriteArrayList<>();

    private static RestClient client() {
        PooledTlsClient pooled = PooledTlsClient.of(SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/orders.crt")
                        .withPrivateKey("classpath:tls/orders.key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))));
        POOLED.add(pooled);
        return pooled.builder().build();
    }

    private record Answer(int status, String body) {
        JsonNode json() throws IOException {
            return JSON.readTree(body);
        }

        String reason() throws IOException {
            return json().path("reason").asText();
        }
    }

    private static KeyringFile ring(long notAfter) {
        return KeyringFile.sign(Map.of("orders", pub(SHOP_KEY)), SHOP_PIN, notAfter, SHOP_POLICY.getPrivate());
    }

    private static PolicyBuilder.Result built(long notAfter) {
        return PolicyBuilder.build(List.of(List.of("orders", PARTNER)), 4, notAfter, SHOP_POLICY.getPrivate());
    }

    private record Opened(String sess, String status) {
    }

    private Opened handshake(RestClient client, SignedRoot root, KeyringFile ring) throws IOException {
        SessionRequest req = SessionRequest.of(root, SHOP_PIN, ring, Sessions.newNonce());
        JsonNode reply = JSON.readTree(client.post()
                .uri("https://localhost:" + port + HttpSessions.PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .body(req.toJson().getBytes(StandardCharsets.UTF_8))
                .retrieve()
                .body(String.class));
        return new Opened(reply.get("sess").asText(), reply.get("status").asText());
    }

    /**
     * The headers of a boundary call in {@code sess}, stamped by the moved clock and carrying the {@code built}
     * proofs.
     */
    private static Map<String, String> boundary(String sess, String rid, PolicyBuilder.Result built) {
        List<Stamp> chain = new Stamper("gateway", "gw-1", GATEWAY_KEY.getPrivate(), true, () -> rid,
                CLOCK::millis).next(null, "orders", "unused", List.of(), null).chain();
        Stamper.Stamped stamped = new Stamper("orders", "orders-1", SHOP_KEY.getPrivate(), false, () -> "unused",
                CLOCK::millis).boundary(chain, sess, PARTNER, RequestBinding.compute("POST", "/refund", REFUND),
                        INFLUENCE, built.bundles().get("orders"));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(PaztportHeaders.SESSION, sess);
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
        headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
        headers.put(PaztportHeaders.INFLUENCE, HttpWire.encodeInfluence(INFLUENCE));
        return headers;
    }

    private Answer call(RestClient client, String method, String path, Map<String, String> headers, byte[] body) {
        RestClient.RequestBodySpec spec = client.method(org.springframework.http.HttpMethod.valueOf(method))
                .uri(URI.create("https://localhost:" + port + path))
                .headers(h -> headers.forEach(h::set));
        if (body != null) {
            spec = spec.contentType(MediaType.APPLICATION_JSON).body(body);
        }
        return spec.exchange((request, response) -> new Answer(response.getStatusCode().value(),
                new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }

    private List<String> warnings() {
        return logs.list.stream().filter(e -> e.getLevel() == Level.WARN).map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    /** An unsafe session, even when it sends what an attested call would, never reaches a disabled write. */
    private void assertUnsafeSession(RestClient client, Opened opened, PolicyBuilder.Result built) throws IOException {
        assertEquals("unsafe", opened.status());
        Answer refund = call(client, "POST", "/refund", boundary(opened.sess(), "rid-u", built), REFUND);
        assertEquals(403, refund.status(), refund.body());
        assertEquals("{\"reason\":\"UNSAFE_SESSION\"}", refund.body());
        Answer statement = call(client, "GET", "/statement", Map.of(PaztportHeaders.SESSION, opened.sess()), null);
        assertEquals(200, statement.status(), statement.body());
        assertEquals("unsafe", statement.json().get("session").asText());
    }

    // A partner whose own root has expired keeps serving: it says "unsafe" in every reply, switches off what it
    // switches off for any unattested caller, and logs why, once.
    @Test
    void partnerDegradesWhenOwnRootExpires() throws Exception {
        RestClient orders = client();
        PolicyBuilder.Result shop = built(START + 30 * DAY_MS);
        KeyringFile shopRing = ring(START + 30 * DAY_MS);
        assertEquals("attested", handshake(orders, shop.signedRoot(), shopRing).status(), "before the partner lapses");

        CLOCK.moveTo(START + 4 * DAY_MS);
        Opened first = handshake(orders, shop.signedRoot(), shopRing);
        assertUnsafeSession(orders, first, shop);
        assertEquals("unsafe", handshake(orders, shop.signedRoot(), shopRing).status());

        assertThat(warnings()).hasSize(1);
        assertThat(warnings().get(0)).contains("own root and keyring has expired").contains("policy tool");
    }

    @Test
    void clientMaterialExpiredOpensAnUnsafeSession() throws Exception {
        RestClient orders = client();
        PolicyBuilder.Result lapsing = built(START + DAY_MS);
        PolicyBuilder.Result lasting = built(START + 30 * DAY_MS);
        KeyringFile lapsingRing = ring(START + DAY_MS);
        KeyringFile lastingRing = ring(START + 30 * DAY_MS);
        CLOCK.moveTo(START + 2 * DAY_MS);

        assertUnsafeSession(orders, handshake(orders, lapsing.signedRoot(), lastingRing), lasting);
        assertUnsafeSession(orders, handshake(orders, lasting.signedRoot(), lapsingRing), lasting);
        assertThat(warnings()).as("the partner's own material is current").isEmpty();
    }

    // Client material without a notAfter is malformed: the handshake is answered 400 INVALID_PARAMS, and no
    // session is opened.
    @Test
    void clientMaterialWithoutNotAfterIsInvalidParams() throws Exception {
        RestClient orders = client();
        ObjectNode req = (ObjectNode) JSON.readTree(SessionRequest.of(built(START + 30 * DAY_MS).signedRoot(),
                SHOP_PIN, ring(START + 30 * DAY_MS), Sessions.newNonce()).toJson());
        ObjectNode noRingWindow = req.deepCopy();
        noRingWindow.remove("clientKeyringNotAfter");
        ObjectNode noRootWindow = req.deepCopy();
        ((ObjectNode) noRootWindow.get("clientRoot")).remove("notAfter");
        for (ObjectNode body : List.of(noRingWindow, noRootWindow)) {
            Answer answer = call(orders, "POST", HttpSessions.PATH, Map.of(),
                    body.toString().getBytes(StandardCharsets.UTF_8));
            assertEquals(new Answer(400, "{\"error\":\"INVALID_PARAMS\"}"), answer);
        }
    }

    // The verifier made for an attested session carries its client's earlier window, so the moment either lapses
    // every call in the session is refused, though the session itself is still known.
    @Test
    void sessionRefusedOnceClientMaterialExpires() throws Exception {
        RestClient orders = client();
        for (boolean keyringFirst : new boolean[] {true, false}) {
            long soon = START + DAY_MS;
            long later = START + 30 * DAY_MS;
            PolicyBuilder.Result shop = built(keyringFirst ? later : soon);
            Opened opened = handshake(orders, shop.signedRoot(), ring(keyringFirst ? soon : later));
            assertEquals("attested", opened.status());
            assertEquals(200, call(orders, "POST", "/refund", boundary(opened.sess(), "rid-a" + keyringFirst, shop),
                    REFUND).status());

            CLOCK.moveTo(START + 2 * DAY_MS);
            Answer expired = call(orders, "POST", "/refund", boundary(opened.sess(), "rid-b" + keyringFirst, shop),
                    REFUND);
            assertEquals(403, expired.status(), expired.body());
            assertEquals("POLICY_EXPIRED", expired.reason());
            CLOCK.moveTo(START);
        }
    }
}
