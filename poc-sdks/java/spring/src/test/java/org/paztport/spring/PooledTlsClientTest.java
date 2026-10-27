// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.StamperV3;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * The starter's pooled client on a real mutual-TLS connection: the bundle's protocols are honoured, the server's
 * name is always checked, and the stamping interceptor gets every kind of answer over it, refusals and empty bodies
 * included, without one turning into an exception or costing the pooled connection.
 */
class PooledTlsClientTest {

    private HttpsServer server;
    private final List<Integer> ports = new CopyOnWriteArrayList<>();
    private final List<PooledTlsClient> clients = new ArrayList<>();

    @AfterEach
    void stop() {
        clients.forEach(PooledTlsClient::close);
        if (server != null) {
            server.stop(0);
        }
    }

    /** A pooled client presenting {@code bundle}, closed after the test. */
    private PooledTlsClient pooled(SslBundle bundle) {
        PooledTlsClient client = PooledTlsClient.of(bundle);
        clients.add(client);
        return client;
    }

    private static PemSslStoreBundle stores(String name) {
        return new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/" + name + ".crt")
                        .withPrivateKey("classpath:tls/" + name + ".key"),
                PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"));
    }

    /** What each path answers: a status and a body, where a null body sends none at all. */
    private record Answer(int status, String body) {
    }

    private static final Map<String, Answer> ANSWERS = Map.of(
            "/ok", new Answer(200, "ok"),
            "/refuse", new Answer(403, "{\"reason\":\"PEER_MISMATCH\"}"),
            "/fail", new Answer(500, "boom"),
            "/none", new Answer(204, null),
            "/empty", new Answer(200, null));

    /** Payment's certificate on the loopback address, asking for a client's, speaking only {@code protocols}. */
    private String serve(String... protocols) throws IOException {
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(SslBundle.of(stores("payment")).createSslContext()) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = getSSLContext().getDefaultSSLParameters();
                ssl.setNeedClientAuth(true);
                if (protocols.length > 0) {
                    ssl.setProtocols(protocols);
                }
                params.setSSLParameters(ssl);
            }
        });
        server.createContext("/", exchange -> {
            ports.add(exchange.getRemoteAddress().getPort());
            exchange.getRequestBody().readAllBytes();
            Answer answer = ANSWERS.get(exchange.getRequestURI().getPath());
            if (answer.body() == null) {
                exchange.sendResponseHeaders(answer.status(), -1);
            } else {
                byte[] body = answer.body().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(answer.status(), body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        server.start();
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    private static Answer call(RestClient client, String url) {
        return client.post().uri(url).body("{}").exchange((request, response) -> {
            byte[] body = response.getBody().readAllBytes();
            return new Answer(response.getStatusCode().value(),
                    body.length == 0 ? null : new String(body, StandardCharsets.UTF_8));
        });
    }

    @Test
    void itSpeaksHttp11AndAlwaysChecksTheServersName() {
        HttpClient http = pooled(SslBundle.of(stores("orders"))).httpClient();

        assertThat(http.version()).isEqualTo(HttpClient.Version.HTTP_1_1);
        assertThat(http.connectTimeout()).contains(PooledTlsClient.CONNECT_TIMEOUT);
        assertThat(http.sslParameters().getEndpointIdentificationAlgorithm()).isEqualTo("HTTPS");
    }

    @Test
    void theBundlesProtocolsAreHonoured() throws Exception {
        String url = serve("TLSv1.3");
        SslBundle tls12 = SslBundle.of(stores("orders"), SslBundleKey.NONE,
                SslOptions.of(null, new String[] {"TLSv1.2"}));
        PooledTlsClient restricted = pooled(tls12);

        assertThat(restricted.httpClient().sslParameters().getProtocols()).containsExactly("TLSv1.2");
        assertThat(restricted.httpClient().sslParameters().getEndpointIdentificationAlgorithm())
                .as("naming protocols does not turn the name check off").isEqualTo("HTTPS");
        assertThatThrownBy(() -> call(restricted.builder().build(), url + "/ok"))
                .isInstanceOf(RestClientException.class)
                .hasRootCauseInstanceOf(SSLHandshakeException.class);
        assertThat(ports).as("never reached the handler").isEmpty();

        assertThat(call(pooled(SslBundle.of(stores("orders"))).builder().build(), url + "/ok"))
                .isEqualTo(new Answer(200, "ok"));
    }

    /**
     * The interceptor reads the status, then the whole body, before the caller sees either. Over the pooled
     * client a refusal, a failure, a 204 and an empty 200 all come back as they were sent, each counts as one
     * untrusted entry, and none of them costs the connection, so the next call still finds it in the pool. The
     * calls are sequential, so all six share exactly one connection; an answer that dropped it would show as two.
     */
    @Test
    void theStampingClientGetsEveryAnswerOverOnePooledConnection() throws Exception {
        String url = serve();
        StamperV3 gateway = new StamperV3("gateway", "gw-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> "rid-1", System::currentTimeMillis);
        RestClient client = pooled(SslBundle.of(stores("gateway"))).builder()
                .requestInterceptor(new OutboundInterceptor(gateway, null, null, "gateway"))
                .build();
        List<String> paths = List.of("/refuse", "/ok", "/fail", "/none", "/empty", "/ok");

        try (PaztportContext.Scope scope = PaztportContext.open()) {
            for (String path : paths) {
                assertThat(call(client, url + path)).as(path).isEqualTo(ANSWERS.get(path));
            }
            assertThat(PaztportContext.influence()).hasSize(paths.size())
                    .extracting(InfluenceEntry::cls).containsOnly(InfluenceClass.LOCAL_UNTRUSTED);
        }
        assertThat(ports).hasSize(paths.size());
        assertThat(ports.stream().distinct().count()).as("connections for %s calls: %s", paths.size(), ports)
                .isEqualTo(1);
    }
}
