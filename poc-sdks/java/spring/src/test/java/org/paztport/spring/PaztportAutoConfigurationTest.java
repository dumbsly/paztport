// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.ReasonCode;
import org.paztport.core.ReplyCert;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;
import org.paztport.core.VerifyInputV3;
import org.paztport.http.PaztportHeaders;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

class PaztportAutoConfigurationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PaztportAutoConfiguration.class));

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** A world shaped like keygen and policy-tool output: a signed keyring, its pin, a root and a bundle. */
    private Path writeWorld(Path dir) throws Exception {
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));
        Files.writeString(dir.resolve("policy.pub"), pub(policy) + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("gateway", pub(gateway)), pub(policy), policy.getPrivate()));
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4, policy.getPrivate());
        JSON.writeValue(dir.resolve("root.json").toFile(), built.signedRoot());
        JSON.writeValue(dir.resolve("proofs-gateway.json").toFile(), built.bundles().get("gateway"));
        return dir;
    }

    private static String[] trust(Path dir) {
        return new String[] {
            "paztport.keyring-path=" + dir.resolve("keyring.json"),
            "paztport.root-path=" + dir.resolve("root.json"),
            "paztport.policy-key-path=" + dir.resolve("policy.pub")};
    }

    private static final String[] VERIFIER_PROPS = {
        "paztport.service-name=payment", "paztport.verify=true"};

    @Test
    void callerGetsStamperAndRestClientCustomizerButNoVerifier(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(
                        "paztport.service-name=gateway",
                        "paztport.origin=true",
                        "paztport.key-path=" + dir.resolve("gateway.key"),
                        "paztport.proofs-path=" + dir.resolve("proofs-gateway.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(StamperV3.class);
                    assertThat(context).hasSingleBean(RestClientCustomizer.class);
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(VerifierV3.class);
                });
    }

    @Test
    void verifierServiceGetsVerifierAndFilterButNoStamper(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> {
                    assertThat(context).hasSingleBean(VerifierV3.class);
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(StamperV3.class);
                });
    }

    @Test
    void theVerifierNeedsAllThreeTrustPaths(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        String[] all = trust(dir);
        runner.withPropertyValues(all).run(context -> assertThat(context).hasSingleBean(VerifierV3.class));
        for (int left = 0; left < all.length; left++) {
            List<String> some = new ArrayList<>(List.of(all));
            some.remove(left);
            runner.withPropertyValues(some.toArray(String[]::new))
                    .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(VerifierV3.class));
        }
    }

    @Test
    void verifyingWithoutTheTrustPathsFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues("paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void anUnsignedKeyringFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                new KeyringFile(Map.of("gateway", pub(gateway)), pub(policy), null));
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aKeyringSignedUnderAnotherKeyFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        KeyPair other = Crypto.generateEd25519KeyPair();
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("gateway", pub(gateway)), pub(other), other.getPrivate()));
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context).hasFailed());
    }

    /**
     * Every caller spends a key per response and every attesting hop one per request, so a cache that never forgot
     * would grow without end. It must still remember for twice the call window, or the verifier refuses everything.
     */
    @Test
    void theReplayCacheForgetsButNotBeforeTheVerifierNeedsIt(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        for (long maxAge : new long[] {5000, 20_000}) {
            runner.withPropertyValues(VERIFIER_PROPS)
                    .withPropertyValues(trust(dir))
                    .withPropertyValues("paztport.max-age-ms=" + maxAge)
                    .run(context -> {
                        VerifierV3 verifier = context.getBean(VerifierV3.class);
                        assertThat(verifier.callMaxAgeMs()).isEqualTo(maxAge);
                        assertThat(verifier.nonceTtlMs()).isNotEqualTo(Long.MAX_VALUE)
                                .isEqualTo(Math.max(VerifierConfigV3.NONCE_TTL_MS, 2 * maxAge));
                        assertThat(Math.floorDiv(verifier.nonceTtlMs(), 2)).isGreaterThanOrEqualTo(maxAge);

                        // The guard holds, so a fresh request verifies rather than failing closed as a replay.
                        StamperV3.Stamped sent = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true,
                                () -> "rid-" + maxAge, System::currentTimeMillis)
                                .next(null, "orders", "b", List.of(),
                                        ConfigLoader.loadProofBundle(dir.resolve("proofs-gateway.json")));
                        VerifyInputV3 input = new VerifyInputV3(JSON.valueToTree(sent.chain().stream()
                                .map(StampV3::toJson).toList()), "b", JSON.createArrayNode(),
                                JSON.valueToTree(sent.proof()), "orders", true, "rid-" + maxAge + "|gateway|req",
                                null);
                        assertThat(verifier.verify(input).reason()).isEqualTo(ReasonCode.OK);
                        assertThat(verifier.verify(input).reason()).isEqualTo(ReasonCode.REPLAY);
                    });
        }
    }

    @Test
    void runMaxAgeIsUnsetUnlessConfigured() {
        runner.run(context -> assertThat(context.getBean(PaztportProperties.class).getRunMaxAgeMs()).isNull());
        runner.withPropertyValues("paztport.run-max-age-ms=60000")
                .run(context -> assertThat(context.getBean(PaztportProperties.class).getRunMaxAgeMs())
                        .isEqualTo(60_000L));
    }

    @Test
    void responderUrlWithoutAnEventKeyFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .withPropertyValues("paztport.responder-url=http://responder:8080")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void responderUrlWithAnEventKeyGetsTheResponderPublisher(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .withPropertyValues(
                        "paztport.responder-url=http://responder:8080",
                        "paztport.event-key-path=" + dir.resolve("gateway.key"))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(ResponderEventPublisher.class));
    }

    @Test
    void noResponderUrlNeedsNoEventKey(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(LoggingEventPublisher.class));
    }

    private final KeyPair psp = Crypto.generateEd25519KeyPair();
    private final KeyPair ledger = Crypto.generateEd25519KeyPair();
    private static final long DAY_MS = 86_400_000L;

    /**
     * A partner's world: its keyring naming {@code psp} and {@code ledger}, signed under its pin, {@code psp}'s key,
     * a week's reply certificate for it, a root, and the pin of the one organisation it attests.
     */
    private Path writePartner(Path dir) throws Exception {
        Files.writeString(dir.resolve("psp.key"), Base64Url.encode(Crypto.encodePrivateKey(psp.getPrivate())));
        Files.writeString(dir.resolve("ledger.key"), Base64Url.encode(Crypto.encodePrivateKey(ledger.getPrivate())));
        Files.writeString(dir.resolve("policy.pub"), pub(policy) + "\n");
        Files.writeString(dir.resolve("shop-policy.pub"), pub(Crypto.generateEd25519KeyPair()) + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("psp", pub(psp), "ledger", pub(ledger)), pub(policy), policy.getPrivate()));
        JSON.writeValue(dir.resolve("root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, policy.getPrivate()).signedRoot());
        writeCert(dir, ReplyCert.issue(pub(policy), "psp", pub(psp), System.currentTimeMillis() + 7 * DAY_MS,
                policy.getPrivate()));
        return dir;
    }

    private static void writeCert(Path dir, ReplyCert cert) throws IOException {
        JSON.writeValue(dir.resolve("reply-cert.json").toFile(), cert.toJson());
    }

    /** Everything partner mode needs, and no policy private key. */
    private static String[] partner(Path dir) {
        return new String[] {
            "paztport.service-name=psp",
            "paztport.keyring-path=" + dir.resolve("keyring.json"),
            "paztport.root-path=" + dir.resolve("root.json"),
            "paztport.policy-key-path=" + dir.resolve("policy.pub"),
            "paztport.key-path=" + dir.resolve("psp.key"),
            "paztport.partner.enabled=true",
            "paztport.partner.reply-cert-path=" + dir.resolve("reply-cert.json"),
            "paztport.partner.client-policy-key-paths[0]=" + dir.resolve("shop-policy.pub"),
            "paztport.partner.client-origins[0]=payment"};
    }

    /** Asserts that partner mode fails to start, naming {@code property} and no key material. */
    private void partnerFails(Path dir, String property, String... overrides) {
        runner.withPropertyValues(partner(dir)).withPropertyValues(overrides)
                .run(context -> {
                    assertThat(context).hasFailed().getFailure().hasStackTraceContaining(property);
                    String trace = stackTrace(context.getStartupFailure());
                    for (KeyPair k : List.of(psp, ledger, policy)) {
                        assertThat(trace).doesNotContain(pub(k))
                                .doesNotContain(Base64Url.encode(Crypto.encodePrivateKey(k.getPrivate())));
                    }
                });
    }

    private static String stackTrace(Throwable t) {
        java.io.StringWriter out = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(out));
        return out.toString();
    }

    // The policy private key stays offline: replies are signed by the entry service's own key.
    @Test
    void partnerStartsWithNoPolicyPrivateKey(@TempDir Path dir) throws Exception {
        writePartner(dir);
        runner.withPropertyValues(partner(dir))
                .run(context -> assertThat(context).hasNotFailed().hasSingleBean(PartnerSessions.class));
    }

    @Test
    void partnerNeedsItsKeyAndCertificate(@TempDir Path dir) throws Exception {
        writePartner(dir);
        List<String> props = new ArrayList<>(List.of(partner(dir)));
        props.removeIf(p -> p.startsWith("paztport.key-path=") || p.startsWith("paztport.partner.reply-cert-path="));
        runner.withPropertyValues(props.toArray(String[]::new))
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining(
                        "paztport.partner.enabled is set but these are not: paztport.key-path, "
                                + "paztport.partner.reply-cert-path"));
    }

    // Forged: a keyring that is not signed under the pin. The shared verifier, which every partner has, may refuse
    // it first, so only the shared part of the two messages is asserted.
    @Test
    void partnerKeyringMustVerifyUnderThePin(@TempDir Path dir) throws Exception {
        writePartner(dir);
        KeyPair other = Crypto.generateEd25519KeyPair();
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("psp", pub(psp)), pub(other), other.getPrivate()));
        partnerFails(dir, "does not verify under");
    }

    @Test
    void partnerKeyringMustHoldTheService(@TempDir Path dir) throws Exception {
        writePartner(dir);
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("ledger", pub(ledger)), pub(policy), policy.getPrivate()));
        partnerFails(dir, "paztport.keyring-path has no key for paztport.service-name");
    }

    @Test
    void partnerKeyMustMatchTheKeyring(@TempDir Path dir) throws Exception {
        writePartner(dir);
        partnerFails(dir, "paztport.key-path does not match", "paztport.key-path=" + dir.resolve("ledger.key"));
    }

    @Test
    void partnerCertificateMustBeThere(@TempDir Path dir) throws Exception {
        writePartner(dir);
        Files.delete(dir.resolve("reply-cert.json"));
        partnerFails(dir, "paztport.partner.reply-cert-path could not be read");
        Files.writeString(dir.resolve("reply-cert.json"), "{\"svc\":\"psp\"}");
        partnerFails(dir, "paztport.partner.reply-cert-path is not a reply certificate");
        // A key file named in its place: the refusal must not quote it. A JSON parser's error quotes the file's
        // first token, the key text up to its first '-' or '_', which starts with the fixed Ed25519 PKCS#8 header.
        runner.withPropertyValues(partner(dir))
                .withPropertyValues("paztport.partner.reply-cert-path=" + dir.resolve("psp.key"))
                .run(context -> {
                    assertThat(context).hasFailed().getFailure()
                            .hasStackTraceContaining("paztport.partner.reply-cert-path is not a reply certificate");
                    assertThat(stackTrace(context.getStartupFailure())).doesNotContain("MC4CAQAwBQYDK2VwBCIEI");
                });
    }

    // Forged: a certificate signed by another policy key, though it names this one.
    @Test
    void partnerCertificateMustVerifyUnderThePin(@TempDir Path dir) throws Exception {
        writePartner(dir);
        ReplyCert forged = ReplyCert.issue(pub(policy), "psp", pub(psp), System.currentTimeMillis() + DAY_MS,
                Crypto.generateEd25519KeyPair().getPrivate());
        writeCert(dir, forged);
        partnerFails(dir, "paztport.partner.reply-cert-path does not verify under paztport.policy-key-path");
    }

    @Test
    void partnerCertificateMustNotHaveExpired(@TempDir Path dir) throws Exception {
        writePartner(dir);
        writeCert(dir, ReplyCert.issue(pub(policy), "psp", pub(psp), System.currentTimeMillis() - 1,
                policy.getPrivate()));
        partnerFails(dir, "paztport.partner.reply-cert-path has expired");
    }

    @Test
    void partnerCertificateMustBeForThisService(@TempDir Path dir) throws Exception {
        writePartner(dir);
        writeCert(dir, ReplyCert.issue(pub(policy), "ledger", pub(ledger), System.currentTimeMillis() + DAY_MS,
                policy.getPrivate()));
        partnerFails(dir, "paztport.partner.reply-cert-path is not for paztport.service-name");
    }

    @Test
    void partnerCertificateMustBeForThisKey(@TempDir Path dir) throws Exception {
        writePartner(dir);
        writeCert(dir, ReplyCert.issue(pub(policy), "psp", pub(ledger), System.currentTimeMillis() + DAY_MS,
                policy.getPrivate()));
        partnerFails(dir, "paztport.partner.reply-cert-path is not for the key at paztport.key-path");
    }

    /**
     * What a test server was sent: the path, the client certificate's CN (null over plain HTTP), the chain, and the
     * port the connection came from, which tells one connection from another.
     */
    private record Received(String path, String peer, String chain, int port) {
    }

    /** Answers 204 to everything, after noting what it was sent. */
    private static void record(HttpExchange exchange, String peer, BlockingQueue<Received> received)
            throws IOException {
        received.add(new Received(exchange.getRequestURI().getPath(), peer,
                exchange.getRequestHeaders().getFirst(PaztportHeaders.CHAIN), exchange.getRemoteAddress().getPort()));
        exchange.sendResponseHeaders(204, -1);
        exchange.close();
    }

    /** The shared builder, the stamping customizer and the SSL bundles as an application would have them. */
    private final ApplicationContextRunner withClients = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    PaztportAutoConfiguration.class, SslAutoConfiguration.class, RestClientAutoConfiguration.class));

    /** A verifying service that also stamps, so the shared builder would stamp anything sent through it. */
    private static String[] stampingVerifier(Path dir, String responderUrl) {
        List<String> props = new ArrayList<>(List.of(VERIFIER_PROPS));
        props.addAll(List.of(trust(dir)));
        props.addAll(List.of(
                "paztport.origin=true",
                "paztport.key-path=" + dir.resolve("gateway.key"),
                "paztport.responder-url=" + responderUrl,
                "paztport.event-key-path=" + dir.resolve("gateway.key")));
        return props.toArray(String[]::new);
    }

    private static final AttestationEvent EVENT =
            new AttestationEvent("PEER_MISMATCH", "gateway", "10.0.0.7", "rid-1", false);

    /** Publishes while a request's scope holds an inbound chain, as the filter does when it refuses one. */
    private static void publishInsideARequest(EventPublisher publisher) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.setInboundChain(List.of(StampV3.sign("gateway", "gw-1", "rid-1", 1L, "", "payment",
                    "b", "", "", Crypto.generateEd25519KeyPair().getPrivate())));
            publisher.publish(EVENT);
        }
    }

    @Test
    void eventsAreNeverStamped(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpServer responder = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        responder.createContext("/", exchange -> record(exchange, null, received));
        responder.start();
        try {
            withClients.withPropertyValues(stampingVerifier(dir,
                            "http://127.0.0.1:" + responder.getAddress().getPort()))
                    .run(context -> {
                        assertThat(context).hasBean("paztportRestClientCustomizer");
                        publishInsideARequest(context.getBean(EventPublisher.class));

                        Received event = received.poll(5, TimeUnit.SECONDS);
                        assertThat(event).isNotNull();
                        assertThat(event.path()).isEqualTo("/events");
                        assertThat(event.chain()).as("an event is not a step on the request's path").isNull();
                    });
        } finally {
            responder.stop(0);
        }
    }

    private static SslBundle fixtureBundle(String name) {
        return SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt")));
    }

    /** A server on the loopback address presenting the fixture certificate {@code name}, asking for a client's. */
    private static HttpsServer mutualTlsServer(String name, BlockingQueue<Received> received) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(fixtureBundle(name).createSslContext()) {
            @Override
            public void configure(HttpsParameters params) {
                params.setNeedClientAuth(true);
            }
        });
        server.createContext("/", exchange -> {
            String peer;
            try {
                peer = PeerIdentity.commonName(
                        (X500Principal) ((HttpsExchange) exchange).getSSLSession().getPeerPrincipal());
            } catch (SSLPeerUnverifiedException e) {
                peer = null;
            }
            record(exchange, peer, received);
        });
        server.start();
        return server;
    }

    /** The {@code mesh} bundle, presenting orders' certificate and trusting the shop's CA. */
    private static final String[] MESH_BUNDLE = {
        "spring.ssl.bundle.pem.mesh.keystore.certificate=classpath:tls/orders.crt",
        "spring.ssl.bundle.pem.mesh.keystore.private-key=classpath:tls/orders.key",
        "spring.ssl.bundle.pem.mesh.truststore.certificate=classpath:tls/ca.crt",
        "paztport.tls-bundle=mesh"};

    @Test
    void theTlsBundleIsPresentedByTheSharedClientAndTheResponderClient(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpsServer server = mutualTlsServer("payment", received);
        String url = "https://127.0.0.1:" + server.getAddress().getPort();
        try {
            withClients.withPropertyValues(stampingVerifier(dir, url))
                    .withPropertyValues(MESH_BUNDLE)
                    .run(context -> {
                        context.getBean(RestClient.Builder.class).build()
                                .post().uri(url + "/call").body("{}").retrieve().toBodilessEntity();
                        Received call = received.poll(5, TimeUnit.SECONDS);
                        assertThat(call).isNotNull();
                        assertThat(call.peer()).isEqualTo("orders");
                        assertThat(call.chain()).as("and the shared client still stamps").isNotNull();

                        publishInsideARequest(context.getBean(EventPublisher.class));
                        Received event = received.poll(5, TimeUnit.SECONDS);
                        assertThat(event).isNotNull();
                        assertThat(event.path()).isEqualTo("/events");
                        assertThat(event.peer()).isEqualTo("orders");
                        assertThat(event.chain()).isNull();
                    });
        } finally {
            server.stop(0);
        }
    }

    /**
     * One client per application, so the shared builder's clients and the responder client draw on one pool: each
     * builder build and each event reuses the connection the first call opened rather than opening its own. The
     * calls are sequential, so one pool means exactly one connection; two pools would show as two.
     */
    @Test
    void theSharedClientAndTheResponderClientShareOnePool(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpsServer server = mutualTlsServer("payment", received);
        String url = "https://127.0.0.1:" + server.getAddress().getPort();
        try {
            withClients.withPropertyValues(stampingVerifier(dir, url))
                    .withPropertyValues(MESH_BUNDLE)
                    .run(context -> {
                        assertThat(context).hasSingleBean(PooledTlsClient.class);
                        List<Integer> ports = new ArrayList<>();
                        for (int i = 0; i < 3; i++) {
                            context.getBean(RestClient.Builder.class).build()
                                    .post().uri(url + "/call").body("{}").retrieve().toBodilessEntity();
                            publishInsideARequest(context.getBean(EventPublisher.class));
                            for (int j = 0; j < 2; j++) {
                                Received r = received.poll(5, TimeUnit.SECONDS);
                                assertThat(r).isNotNull();
                                ports.add(r.port());
                            }
                        }
                        assertThat(ports).hasSize(6);
                        assertThat(ports.stream().distinct().count()).as("connections for 6 calls: %s", ports)
                                .isEqualTo(1);
                    });
        } finally {
            server.stop(0);
        }
    }

    /**
     * The server's certificate must name the host the call was made to. Orders' certificate is the shop CA's and
     * so trusted, but it names only {@code orders}, so a call to it at {@code 127.0.0.1} fails the handshake.
     */
    @Test
    void theSharedClientChecksTheServersNameAgainstItsCertificate(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpsServer server = mutualTlsServer("orders", received);
        String url = "https://127.0.0.1:" + server.getAddress().getPort();
        try {
            withClients.withPropertyValues(stampingVerifier(dir, url))
                    .withPropertyValues(MESH_BUNDLE)
                    .run(context -> {
                        RestClient client = context.getBean(RestClient.Builder.class).build();
                        assertThatThrownBy(() -> client.post().uri(url + "/call").body("{}").retrieve()
                                .toBodilessEntity())
                                .isInstanceOf(RestClientException.class)
                                .rootCause()
                                .isInstanceOf(CertificateException.class)
                                .hasMessageContaining("127.0.0.1");
                        assertThat(received).as("the server's handler never ran").isEmpty();
                    });
        } finally {
            server.stop(0);
        }
    }

    /**
     * The bundle's files are read on the first call, so a service starts, and its tests run, where its certificate
     * is not mounted; the call that needs it is the one that fails.
     */
    @Test
    void aTlsBundleWhoseFilesAreNotThereFailsTheCallNotTheStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        withClients.withPropertyValues(stampingVerifier(dir, "https://127.0.0.1:1"))
                .withPropertyValues(
                        "spring.ssl.bundle.pem.mesh.keystore.certificate=file:" + dir.resolve("absent.crt"),
                        "spring.ssl.bundle.pem.mesh.keystore.private-key=file:" + dir.resolve("absent.key"),
                        "spring.ssl.bundle.pem.mesh.truststore.certificate=classpath:tls/ca.crt",
                        "paztport.tls-bundle=mesh")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(PooledTlsClient.class);
                    RestClient client = context.getBean(RestClient.Builder.class).build();
                    assertThatThrownBy(() -> client.post().uri("https://127.0.0.1:1/call").body("{}").retrieve()
                            .toBodilessEntity())
                            .hasStackTraceContaining("absent.crt");
                });
    }

    @Test
    void aTlsBundleThatDoesNotExistFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        withClients.withPropertyValues(stampingVerifier(dir, "https://127.0.0.1:1"))
                .withPropertyValues("paztport.tls-bundle=missing")
                .run(context -> assertThat(context).hasFailed());
    }
}
