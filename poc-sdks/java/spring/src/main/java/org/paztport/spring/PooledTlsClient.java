// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * One pooled HTTP client that presents an SSL bundle: its key material as the client certificate, its truststore
 * for the server's, and its enabled protocols and ciphers where the bundle names any. Every RestClient built over
 * it shares one connection pool, so calls to a service reuse open mutual-TLS connections instead of each paying a
 * handshake.
 *
 * <p>It exists to give every call to a service one shared connection pool and one timeout. With no Apache, Jetty
 * or Reactor client on the classpath, Spring Boot 4 builds the JDK's {@link HttpClient} for an SSL bundle, but
 * afresh each time the bundle is applied to a {@code RestClient} builder: the {@code RestClient}s built from one
 * builder share its pool, and each further builder gets a pool of its own. One client is made here per bundle and
 * shared by every {@code RestClient} built over it. (Spring Boot 3.3's client for an SSL bundle was worse:
 * {@code HttpURLConnection}, given a new socket factory on every connection, when the JDK's keep-alive cache
 * reuses a connection only for the socket factory that opened it, so every call opened a fresh connection and left
 * it open at the server until its keep-alive timed out.)
 *
 * <p>It speaks HTTP/1.1 only, as Spring Boot's servers do unless configured for HTTP/2, so the connection
 * behaviour stays the same whatever a server offers over ALPN. The server's certificate is checked against the
 * host in the URL, as the JDK client does by default; the parameters set here say so too, so neither naming
 * protocols or ciphers nor the JDK's own switch for its client can turn it off.
 *
 * <p>Two timeouts bound a call through the request factory. The connect timeout, {@link #CONNECT_TIMEOUT}, bounds
 * opening a connection. The read timeout, {@code paztport.read-timeout-ms} (30 s unless set), bounds the whole
 * exchange, from sending the request to the end of the response's body, on every JDK: a peer that takes the call and
 * sends no answer, one that sends its headers and then stops part way through the body, or a pooled connection whose
 * peer has vanished without closing it, fails the call at the read timeout, as a timeout (from a {@code RestClient},
 * a {@code ResourceAccessException}), instead of holding the calling thread for ever. Spring's own JDK request
 * factory, which Spring Boot 4 gives an SSL bundle, ends a stalled body too, since Spring Framework 6.2 (Boot 3.3's
 * 6.1 did not), but not as this class promises: a stall after the headers reaches the caller as a
 * {@code RestClientException} over an {@code IOException} ("closed"), not as a timeout, and Spring Boot sets no
 * read timeout unless one is configured, so without one the call waits for ever. So the factory here is
 * {@link WholeExchangeRequestFactory}, which reads each response whole within the one timeout ({@link #send}) and
 * fails every stall as a timeout. The egress's calls to the partner and the events are bounded by
 * {@link #send} too.
 *
 * <p>The client stamps nothing. {@link #builder()} gives a builder with TLS only, for calls that must not be a
 * step on a request's path or that set their own headers; the starter puts the same request factory on the shared
 * {@code RestClient.Builder}, beside the stamping interceptor, and sends events on the JDK client itself.
 */
public final class PooledTlsClient implements AutoCloseable {

    /** Long enough for a handshake on a loaded host, short enough that an unreachable service fails the call. */
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    /**
     * The read timeout unless one is given: far beyond any answer a working service gives, so it ends only calls
     * that would otherwise wait for ever. {@code paztport.read-timeout-ms} has the same default.
     */
    static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);

    /** The JDK client and Spring's factory over it, made together on the first call. */
    private record Pool(HttpClient http, ClientHttpRequestFactory factory) {
    }

    private final SslBundle bundle;
    private final Duration readTimeout;
    private final ClientHttpRequestFactory requestFactory =
            (uri, method) -> pool().factory().createRequest(uri, method);
    private volatile Pool pool;
    private boolean closed;

    private PooledTlsClient(SslBundle bundle, Duration readTimeout) {
        this.bundle = bundle;
        this.readTimeout = readTimeout;
    }

    /**
     * A client presenting {@code bundle}, with the default read timeout, {@link #DEFAULT_READ_TIMEOUT}. Its key
     * material is read on the first call, not here, as Spring's own SSL clients do, so an application can start,
     * and be tested, where its certificate files are not mounted; a bundle that cannot be read fails every call,
     * clearly, until it can.
     */
    public static PooledTlsClient of(SslBundle bundle) {
        return of(bundle, DEFAULT_READ_TIMEOUT);
    }

    /**
     * As {@link #of(SslBundle)}, with {@code readTimeout} as the read timeout.
     *
     * @throws IllegalArgumentException when {@code readTimeout} is not positive
     */
    public static PooledTlsClient of(SslBundle bundle, Duration readTimeout) {
        Objects.requireNonNull(readTimeout, "readTimeout");
        if (readTimeout.isNegative() || readTimeout.isZero()) {
            throw new IllegalArgumentException("the read timeout must be positive: " + readTimeout);
        }
        return new PooledTlsClient(bundle, readTimeout);
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
                    p = new Pool(http, new WholeExchangeRequestFactory(http, readTimeout));
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

    /**
     * The shared request factory: every RestClient given it draws on this client's one pool, and each of its calls,
     * the response's body included, ends within the read timeout.
     */
    public ClientHttpRequestFactory requestFactory() {
        return requestFactory;
    }

    /**
     * A fresh builder over the shared request factory, with nothing else on it: TLS, and no stamping. Each response
     * is read whole and held in memory before the caller sees it, so it suits the small bodies mesh calls carry,
     * not large streamed downloads.
     */
    public RestClient.Builder builder() {
        return RestClient.builder().requestFactory(requestFactory);
    }

    /** The read timeout of every call through {@link #requestFactory()}. */
    Duration readTimeout() {
        return readTimeout;
    }

    HttpClient httpClient() {
        return pool().http();
    }

    /**
     * Sends {@code request} on {@code http} and waits for the whole answer, its body included, for no longer than
     * the request's timeout, which it must have. Waiting here is what bounds the body on every JDK, since 21 applies
     * a request's timeout only to the wait for the headers (27 applies it to the body too, so there the JDK's own
     * timeout may end the call first). Past it the exchange is cancelled, which closes its connection, and the call
     * fails as an {@link HttpTimeoutException}.
     *
     * @throws IOException when the call fails, has no whole answer within the timeout, or the thread is
     *     interrupted (whose interrupt is kept)
     */
    static <T> HttpResponse<T> send(HttpClient http, HttpRequest request, HttpResponse.BodyHandler<T> body)
            throws IOException {
        Duration timeout = request.timeout()
                .orElseThrow(() -> new IllegalArgumentException("the request must have a timeout"));
        CompletableFuture<HttpResponse<T>> answer = http.sendAsync(request, body);
        try {
            return answer.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            answer.cancel(true);
            throw new HttpTimeoutException("no whole answer within " + timeout.toMillis() + " ms");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw new IOException(e.getCause());
        } catch (InterruptedException e) {
            answer.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
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
