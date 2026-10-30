// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.http.HttpSessions;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.spring.outbound.PooledTlsClient;
import org.paztport.spring.partner.BoundaryClient;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * The partner's request path through the real container under mutual TLS: a boundary chain verifies only in the
 * attested session of the peer that sent it, and an unsafe session, or none, reaches the handlers with no influence
 * and no verified chain, and never reaches an operation switched off for it. The partner's entry is named
 * {@code localhost}, after the fixture certificate it serves; the shop's egress is the fixture {@code orders}.
 */
@SpringBootTest(classes = PartnerRequestTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.banner-mode=off",
            "server.ssl.bundle=psp",
            "server.ssl.client-auth=need",
            "spring.ssl.bundle.pem.psp.keystore.certificate=classpath:tls/payment.crt",
            "spring.ssl.bundle.pem.psp.keystore.private-key=classpath:tls/payment.key",
            "spring.ssl.bundle.pem.psp.truststore.certificate=classpath:tls/ca.crt"})
class PartnerRequestTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PARTNER = "localhost";
    private static final KeyPair SHOP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair SHOP_POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair GATEWAY_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_KEY = Crypto.generateEd25519KeyPair();
    private static final KeyPair PSP_POLICY = Crypto.generateEd25519KeyPair();
    private static final String SHOP_PIN = pub(SHOP_POLICY);
    private static final String PSP_PIN = pub(PSP_POLICY);
    private static final KeyringFile SHOP_RING =
            KeyringFile.sign(Map.of("orders", pub(SHOP_KEY)), SHOP_PIN, NOT_AFTER, SHOP_POLICY.getPrivate());
    private static final PolicyBuilder.Result SHOP_BUILT =
            PolicyBuilder.build(List.of(List.of("orders", PARTNER)), 4, NOT_AFTER, SHOP_POLICY.getPrivate());
    private static final byte[] REFUND = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final List<InfluenceEntry> INFLUENCE = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-ticket", "cid-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-2", "alice"));
    private static Path trust;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @DynamicPropertySource
    static void trustFiles(DynamicPropertyRegistry registry) throws IOException {
        trust = Files.createTempDirectory("paztport-partner-request");
        Files.writeString(trust.resolve("policy.pub"), PSP_PIN + "\n");
        Files.writeString(trust.resolve("entry.key"), Base64Url.encode(Crypto.encodePrivateKey(PSP_KEY.getPrivate())));
        Files.writeString(trust.resolve("shop-policy.pub"), SHOP_PIN + "\n");
        JSON.writeValue(trust.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of(PARTNER, pub(PSP_KEY)), PSP_PIN, NOT_AFTER, PSP_POLICY.getPrivate()));
        Files.writeString(trust.resolve("reply-cert.json"), ReplyCert.issue(PSP_PIN, PARTNER, pub(PSP_KEY),
                System.currentTimeMillis() + 7 * 86_400_000L, PSP_POLICY.getPrivate()).toJson());
        JSON.writeValue(trust.resolve("root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4,
                        NOT_AFTER, PSP_POLICY.getPrivate()).signedRoot());

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
        registry.add("paztport.partner.unsafe-disabled[1]", () -> "GET /statement");
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
    }

    /**
     * Each handler answers with what the request scope held when it ran. The body is written here with the SDK's own
     * Jackson and handed over as a string, so the assertions read the influence exactly as the SDK writes it rather
     * than as the web framework would serialise the SDK's objects.
     */
    @RestController
    static class Handlers {

        @PostMapping(path = "/charge", produces = MediaType.APPLICATION_JSON_VALUE)
        String charge(HttpServletRequest request) throws IOException {
            return seen(request);
        }

        @PostMapping(path = "/refund", produces = MediaType.APPLICATION_JSON_VALUE)
        String refund(HttpServletRequest request) throws IOException {
            return seen(request);
        }

        @GetMapping(path = "/statement", produces = MediaType.APPLICATION_JSON_VALUE)
        String statement(HttpServletRequest request) throws IOException {
            return seen(request);
        }

        private static String seen(HttpServletRequest request) throws IOException {
            ObjectNode seen = JSON.createObjectNode();
            seen.set("influence", JSON.readTree(Influence.toJson(PaztportContext.influence())));
            seen.put("verified", PaztportContext.verifiedChain() != null);
            seen.put("session", (String) request.getAttribute(PartnerFilter.SESSION_STATUS));
            return JSON.writeValueAsString(seen);
        }
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
        PaztportContext.reset();
    }

    private static final List<PooledTlsClient> POOLED = new CopyOnWriteArrayList<>();

    private static SslBundle fixtureBundle(String name) {
        return SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt")));
    }

    /** A pooled client presenting the fixture certificate {@code name} and trusting the shop's CA. */
    private static RestClient client(String name) {
        PooledTlsClient pooled = PooledTlsClient.of(fixtureBundle(name));
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

    /** Opens a session as {@code client}: attested with the shop's root, unsafe without one. */
    private String handshake(RestClient client, boolean withRoot) throws IOException {
        SessionRequest req = SessionRequest.of(withRoot ? SHOP_BUILT.signedRoot() : null, SHOP_PIN, SHOP_RING,
                Sessions.newNonce());
        String reply = client.post()
                .uri("https://localhost:" + port + HttpSessions.PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .body(req.toJson().getBytes(StandardCharsets.UTF_8))
                .retrieve()
                .body(String.class);
        return JSON.readTree(reply).get("sess").asText();
    }

    /** An internal chain the shop's egress verified, as far as the boundary stamp needs one: its rid. */
    private static List<StampV3> internal(String rid) {
        return new StamperV3("gateway", "gw-1", GATEWAY_KEY.getPrivate(), true, () -> rid, System::currentTimeMillis)
                .next(null, "orders", "unused", List.of(), null).chain();
    }

    private static StamperV3 orders() {
        return new StamperV3("orders", "orders-1", SHOP_KEY.getPrivate(), false, () -> "unused",
                System::currentTimeMillis);
    }

    /** The headers of a boundary call from {@code orders} in {@code sess}, carrying {@link #INFLUENCE}. */
    private static Map<String, String> boundary(String sess, String rid, String path, byte[] body) {
        StamperV3.Stamped stamped = orders().boundary(internal(rid), sess, PARTNER,
                RequestBinding.compute("POST", path, body), INFLUENCE, SHOP_BUILT.bundles().get("orders"));
        return headers(sess, stamped.chain(), stamped);
    }

    private static Map<String, String> headers(String sess, List<StampV3> chain, StamperV3.Stamped proofFrom) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (sess != null) {
            headers.put(PaztportHeaders.SESSION, sess);
        }
        headers.put(PaztportHeaders.CHAIN, HttpV3.encodeChain(chain));
        if (proofFrom != null && proofFrom.proof() != null) {
            headers.put(PaztportHeaders.PROOF, HttpV3.encodeProof(proofFrom.proof()));
        }
        headers.put(PaztportHeaders.INFLUENCE, HttpV3.encodeInfluence(INFLUENCE));
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

    private Answer post(RestClient client, String path, Map<String, String> headers, byte[] body) {
        return call(client, "POST", path, headers, body);
    }

    private List<String> lines(String prefix) {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage).filter(l -> l.startsWith(prefix)).toList();
    }

    @Test
    void attestedCallVerifiedWithOwners() throws Exception {
        RestClient orders = client("orders");
        String sess = handshake(orders, true);

        Answer answer = post(orders, "/refund", boundary(sess, "rid-a", "/refund", REFUND), REFUND);

        assertEquals(200, answer.status(), answer.body());
        JsonNode seen = answer.json();
        assertEquals(INFLUENCE, Influence.parse(seen.get("influence").toString()), "both entries, owners included");
        assertTrue(seen.get("verified").asBoolean());
        assertEquals("attested", seen.get("session").asText());
        assertThat(lines("PAZTPORT_TRACE request ")).containsExactly("PAZTPORT_TRACE request rid=rid-a reason=OK "
                + "receiver=localhost ✓ peer=orders (mTLS) classes=private,third-party session=attested");
    }

    @Test
    void internalChainRefused() throws Exception {
        RestClient orders = client("orders");
        String sess = handshake(orders, true);
        String bind = RequestBinding.compute("POST", "/refund", REFUND);

        // The shop's internal chain, sent as it is: gateway, then orders, inside the mesh's empty session.
        List<StampV3> gatewayFirst = new StamperV3("gateway", "gw-1", GATEWAY_KEY.getPrivate(), true, () -> "rid-i",
                System::currentTimeMillis).next(null, "orders", "unused", List.of(), null).chain();
        StamperV3.Stamped twoStamps = orders().next(gatewayFirst, PARTNER, bind, INFLUENCE, null);
        Answer internal = post(orders, "/refund", headers(sess, twoStamps.chain(), null), REFUND);

        assertEquals(403, internal.status());
        assertEquals("BAD_ORIGIN", internal.reason());
        assertEquals("orders", internal.json().get("suspectSvc").asText());

        // One stamp from orders, but in the mesh's empty session rather than this one.
        StamperV3.Stamped meshStamp = new StamperV3("orders", "orders-1", SHOP_KEY.getPrivate(), true,
                () -> "rid-j", System::currentTimeMillis).next(null, PARTNER, bind, INFLUENCE,
                        SHOP_BUILT.bundles().get("orders"));
        Answer mesh = post(orders, "/refund", headers(sess, meshStamp.chain(), meshStamp), REFUND);

        assertEquals(403, mesh.status());
        assertEquals("SESSION_UNKNOWN", mesh.reason());
    }

    @Test
    void replayRefused() throws Exception {
        RestClient orders = client("orders");
        String sess = handshake(orders, true);
        Map<String, String> once = boundary(sess, "rid-r", "/refund", REFUND);

        assertEquals(200, post(orders, "/refund", once, REFUND).status());
        Answer again = post(orders, "/refund", once, REFUND);

        assertEquals(403, again.status());
        assertEquals("REPLAY", again.reason());
    }

    @Test
    void sessionBoundToPeer() throws Exception {
        RestClient orders = client("orders");
        String sess = handshake(orders, true);

        Answer otherPeer = post(client("gateway"), "/refund", boundary(sess, "rid-p1", "/refund", REFUND), REFUND);
        assertEquals(403, otherPeer.status());
        assertEquals("SESSION_UNKNOWN", otherPeer.reason());
        assertEquals("gateway", otherPeer.json().get("suspectSvc").asText());

        Answer madeUp = post(orders, "/refund", boundary("made-up-id", "rid-p2", "/refund", REFUND), REFUND);
        assertEquals(403, madeUp.status());
        assertEquals("SESSION_UNKNOWN", madeUp.reason());

        // An empty id names no session either, and is not taken as no header.
        Answer empty = post(orders, "/charge", Map.of(PaztportHeaders.SESSION, ""), REFUND);
        assertEquals(403, empty.status());
        assertEquals("SESSION_UNKNOWN", empty.reason());

        // A second handshake adds a session and replaces none, so both work, and the refusals above were about
        // the ids alone.
        String second = handshake(orders, true);
        assertEquals(200, post(orders, "/refund", boundary(sess, "rid-p3", "/refund", REFUND), REFUND).status());
        assertEquals(200, post(orders, "/refund", boundary(second, "rid-p4", "/refund", REFUND), REFUND).status());
    }

    @Test
    void unsafeGate() throws Exception {
        RestClient orders = client("orders");
        String unsafe = handshake(orders, false);

        // In the unsafe session, even sending what an attested call would; and again with no session at all.
        for (String sess : new String[] {unsafe, null}) {
            Map<String, String> headers = sess == null
                    ? headers(null, internal("rid-u"), null)
                    : boundary(sess, "rid-u", "/refund", REFUND);

            Answer refund = post(orders, "/refund", headers, REFUND);
            assertEquals(403, refund.status());
            assertEquals("{\"reason\":\"UNSAFE_SESSION\"}", refund.body());

            for (String variant : List.of("/refund;x=1", "//refund", "/refund/")) {
                int status = post(orders, variant, headers, REFUND).status();
                assertTrue(status == 403 || status == 404, variant + " gave " + status);
            }

            Answer statement = call(orders, "HEAD", "/statement", headers, null);
            assertEquals(403, statement.status(), "HEAD runs the GET handler, so it is switched off with it");

            Answer charge = post(orders, "/charge", headers, REFUND);
            assertEquals(200, charge.status(), charge.body());
            JsonNode seen = charge.json();
            assertEquals(0, seen.get("influence").size(), "nothing is taken from an unverified request");
            assertFalse(seen.get("verified").asBoolean());
            assertEquals("unsafe", seen.get("session").asText());
        }

        assertThat(lines("PAZTPORT_TRACE decision ")).contains(
                "PAZTPORT_TRACE decision rid=- receiver=localhost rule=unsafe-session reason=UNSAFE_SESSION ✗ "
                        + "classes=-");
        assertThat(lines("PAZTPORT_TRACE request ")).contains(
                "PAZTPORT_TRACE request rid=rid-u reason=- receiver=localhost peer=orders (mTLS) session=unsafe");
        assertThat(lines("PAZTPORT_TRACE request ")).allMatch(l -> l.endsWith(" session=unsafe"));
    }

    @Test
    void unsafeRequestWithNoChainTracesNoRid() throws Exception {
        Answer charge = post(client("orders"), "/charge", Map.of(), REFUND);

        assertEquals(200, charge.status());
        assertThat(lines("PAZTPORT_TRACE request ")).containsExactly(
                "PAZTPORT_TRACE request rid=- reason=- receiver=localhost peer=orders (mTLS) session=unsafe");
    }

    // The egress sends the influence blinded, and the partner verifies the boundary stamp's commitment to it and
    // applies the owner-aware rule to its classes and owners, which survive.
    @Test
    void roundTrip() throws Exception {
        PooledTlsClient tls = PooledTlsClient.of(fixtureBundle("orders"));
        byte[] blindingKey = new java.security.SecureRandom().generateSeed(BoundaryInfluence.KEY_LENGTH);
        try (BoundaryClient boundary = new BoundaryClient(orders(), SHOP_BUILT.bundles().get("orders"),
                SHOP_BUILT.signedRoot(), SHOP_RING, SHOP_PIN, PARTNER, URI.create("https://localhost:" + port),
                PSP_PIN, blindingKey, null, tls, 600_000)) {
            for (String rid : List.of("rid-t1", "rid-t2")) {
                try (PaztportContext.Scope scope = PaztportContext.open()) {
                    PaztportContext.markVerified(internal(rid));
                    PaztportContext.addInfluence(INFLUENCE.toArray(InfluenceEntry[]::new));

                    BoundaryClient.Response response = boundary.post("/refund", REFUND);

                    assertEquals(200, response.status(), new String(response.body(), StandardCharsets.UTF_8));
                    assertTrue(response.attested());
                    JsonNode seen = JSON.readTree(response.body());
                    assertEquals(BoundaryInfluence.reduce(INFLUENCE, blindingKey, rid, PARTNER, "orders"),
                            Influence.parse(seen.get("influence").toString()));
                    assertTrue(seen.get("verified").asBoolean());
                }
            }
        }

        assertEquals(1, lines("PAZTPORT_TRACE session peer=orders ").size(), "one handshake for both calls");
    }
}
