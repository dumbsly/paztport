// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

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
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierV3;
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

    /** What a test server was sent: the path, the client certificate's CN (null over plain HTTP) and the chain. */
    private record Received(String path, String peer, String chain) {
    }

    /** Answers 204 to everything, after noting what it was sent. */
    private static void record(HttpExchange exchange, String peer, BlockingQueue<Received> received)
            throws IOException {
        received.add(new Received(exchange.getRequestURI().getPath(), peer,
                exchange.getRequestHeaders().getFirst(PaztportHeaders.CHAIN)));
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

    @Test
    void theTlsBundleIsPresentedByTheSharedClientAndTheResponderClient(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        BlockingQueue<Received> received = new LinkedBlockingQueue<>();
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(fixtureBundle("payment").createSslContext()) {
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
        String url = "https://127.0.0.1:" + server.getAddress().getPort();
        try {
            withClients.withPropertyValues(stampingVerifier(dir, url))
                    .withPropertyValues(
                            "spring.ssl.bundle.pem.mesh.keystore.certificate=classpath:tls/orders.crt",
                            "spring.ssl.bundle.pem.mesh.keystore.private-key=classpath:tls/orders.key",
                            "spring.ssl.bundle.pem.mesh.truststore.certificate=classpath:tls/ca.crt",
                            "paztport.tls-bundle=mesh")
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

    @Test
    void aTlsBundleThatDoesNotExistFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        withClients.withPropertyValues(stampingVerifier(dir, "https://127.0.0.1:1"))
                .withPropertyValues("paztport.tls-bundle=missing")
                .run(context -> assertThat(context).hasFailed());
    }
}
