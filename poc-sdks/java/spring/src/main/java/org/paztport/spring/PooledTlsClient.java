// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.net.http.HttpClient;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * One pooled HTTP client that presents an SSL bundle: its key material as the client certificate, its truststore
 * for the server's, and its enabled protocols and ciphers where the bundle names any. Every RestClient built over
 * it shares one connection pool, so calls to a service reuse open mutual-TLS connections instead of each paying a
 * handshake.
 *
 * <p>It exists because the client Spring Boot 3.3 builds for an SSL bundle never reuses a connection: it is
 * {@code HttpURLConnection}, given a new socket factory on every connection, and the JDK's keep-alive cache only
 * reuses a connection for the socket factory that opened it. So every call opens a fresh connection and leaves
 * each one open at the server until its keep-alive times out, and under steady load the server reaches its
 * connection limit and stops accepting. The JDK's {@link HttpClient} pools per client instead, so one client is
 * made per bundle and shared.
 *
 * <p>It speaks HTTP/1.1 only, as Spring Boot's servers do unless configured for HTTP/2, so the connection
 * behaviour stays the same whatever a server offers over ALPN. The server's certificate is checked against the
 * host in the URL, as the JDK client does by default; the parameters set here say so too, so neither naming
 * protocols or ciphers nor the JDK's own switch for its client can turn it off.
 *
 * <p>Only a connect timeout is set, not a read timeout: a pooled connection whose peer vanishes without closing it
 * can block a call until TCP itself gives up.
 *
 * <p>The client stamps nothing. {@link #builder()} gives a builder with TLS only, for calls that must not be a
 * step on a request's path (events) or that set their own headers; the starter puts the same request factory on
 * the shared {@code RestClient.Builder}, beside the stamping interceptor.
 */
public final class PooledTlsClient implements AutoCloseable {

    /** Long enough for a handshake on a loaded host, short enough that an unreachable service fails the call. */
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    /** The JDK client and Spring's factory over it, made together on the first call. */
    private record Pool(HttpClient http, ClientHttpRequestFactory factory) {
    }

    private final SslBundle bundle;
    private final ClientHttpRequestFactory requestFactory =
            (uri, method) -> pool().factory().createRequest(uri, method);
    private volatile Pool pool;
    private boolean closed;

    private PooledTlsClient(SslBundle bundle) {
        this.bundle = bundle;
    }

    /**
     * A client presenting {@code bundle}. Its key material is read on the first call, not here, as Spring's own
     * SSL clients do, so an application can start, and be tested, where its certificate files are not mounted; a
     * bundle that cannot be read fails every call, clearly, until it can.
     */
    public static PooledTlsClient of(SslBundle bundle) {
        return new PooledTlsClient(bundle);
    }

    private Pool pool() {
        Pool p = pool;
        if (p == null) {
            synchronized (this) {
                if (closed) {
                    throw new IllegalStateException("the TLS client is closed");
                }
                p = pool;
                if (p == null) {
                    SSLContext context = bundle.createSslContext();
                    HttpClient http = HttpClient.newBuilder()
                            .version(HttpClient.Version.HTTP_1_1)
                            .connectTimeout(CONNECT_TIMEOUT)
                            .sslContext(context)
                            .sslParameters(parameters(context, bundle.getOptions()))
                            .build();
                    p = new Pool(http, new JdkClientHttpRequestFactory(http));
                    pool = p;
                }
            }
        }
        return p;
    }

    /**
     * The context's defaults, narrowed to the bundle's protocols and ciphers where it names them, and checking the
     * server's certificate against the host it was asked for.
     */
    static SSLParameters parameters(SSLContext context, SslOptions options) {
        SSLParameters params = context.getDefaultSSLParameters();
        if (options.getEnabledProtocols() != null) {
            params.setProtocols(options.getEnabledProtocols());
        }
        if (options.getCiphers() != null) {
            params.setCipherSuites(options.getCiphers());
        }
        params.setEndpointIdentificationAlgorithm("HTTPS");
        return params;
    }

    /** The shared request factory: every RestClient given it draws on this client's one pool. */
    public ClientHttpRequestFactory requestFactory() {
        return requestFactory;
    }

    /** A fresh builder over the shared request factory, with nothing else on it: TLS, and no stamping. */
    public RestClient.Builder builder() {
        return RestClient.builder().requestFactory(requestFactory);
    }

    HttpClient httpClient() {
        return pool().http();
    }

    /**
     * Stops taking new calls and lets the pool's connections close once the calls in flight finish. It does not
     * wait for them, so a call with no answer cannot hold up the application's shutdown.
     */
    @Override
    public synchronized void close() {
        closed = true;
        if (pool != null) {
            pool.http().shutdown();
        }
    }
}
