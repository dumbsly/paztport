// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.AbstractClientHttpRequest;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Spring's request factory over a JDK client, with each call bounded whole, by {@link PooledTlsClient#send}:
 * connecting, sending, the response's headers and its body, on every JDK. It exists because Spring's own
 * {@code JdkClientHttpRequestFactory} hands back the body as a stream, so its read timeout bounds only the wait for
 * the headers, and on JDK 21 a peer that sends its headers and then stops holds the call for ever.
 *
 * <p>So the request body is buffered and the response's is read whole before the caller sees either. Nothing is lost
 * by it: the stamping interceptor reads every response whole anyway, to bind the result hash, and holds the request
 * body to bind the request. Status, headers and body come back as sent, error statuses and empty bodies included.
 */
final class WholeExchangeRequestFactory implements ClientHttpRequestFactory {

    /** Headers the JDK client sets itself and refuses from the caller, as Spring's own JDK request leaves out. */
    private static final Set<String> SET_BY_THE_CLIENT = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

    static {
        SET_BY_THE_CLIENT.addAll(Set.of("connection", "content-length", "expect", "host", "upgrade"));
    }

    private final HttpClient http;
    private final Duration timeout;

    /** Calls on {@code http}, each of which must end within {@code timeout}. */
    WholeExchangeRequestFactory(HttpClient http, Duration timeout) {
        this.http = http;
        this.timeout = timeout;
    }

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod method) {
        return new Request(uri, method);
    }

    private final class Request extends AbstractClientHttpRequest {
        private final URI uri;
        private final HttpMethod method;
        private final ByteArrayOutputStream body = new ByteArrayOutputStream();

        Request(URI uri, HttpMethod method) {
            this.uri = uri;
            this.method = method;
        }

        @Override
        public HttpMethod getMethod() {
            return method;
        }

        @Override
        public URI getURI() {
            return uri;
        }

        @Override
        protected OutputStream getBodyInternal(HttpHeaders headers) {
            return body;
        }

        @Override
        protected ClientHttpResponse executeInternal(HttpHeaders headers) throws IOException {
            HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(timeout);
            headers.forEach((name, values) -> {
                if (!SET_BY_THE_CLIENT.contains(name)) {
                    values.forEach(value -> request.header(name, value));
                }
            });
            byte[] bytes = body.toByteArray();
            request.method(method.name(), bytes.length == 0
                    ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(bytes));
            return new Response(PooledTlsClient.send(http, request.build(), HttpResponse.BodyHandlers.ofByteArray()));
        }
    }

    /** A response read whole: one stream over its body, as Spring's own gives, and nothing left to release. */
    private static final class Response implements ClientHttpResponse {
        private final HttpResponse<byte[]> response;
        private final InputStream body;

        Response(HttpResponse<byte[]> response) {
            this.response = response;
            this.body = new ByteArrayInputStream(response.body() == null ? new byte[0] : response.body());
        }

        @Override
        public HttpStatusCode getStatusCode() {
            return HttpStatusCode.valueOf(response.statusCode());
        }

        @Override
        public String getStatusText() {
            HttpStatus status = HttpStatus.resolve(response.statusCode());
            return status == null ? "" : status.getReasonPhrase();
        }

        @Override
        public HttpHeaders getHeaders() {
            HttpHeaders headers = new HttpHeaders();
            response.headers().map().forEach(headers::addAll);
            return HttpHeaders.readOnlyHttpHeaders(headers);
        }

        @Override
        public InputStream getBody() {
            return body;
        }

        @Override
        public void close() {
        }
    }
}
