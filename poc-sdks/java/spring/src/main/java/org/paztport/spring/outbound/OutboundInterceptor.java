// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.HttpCaller;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.PaztportHeaders;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Stamps every outbound RestClient request, and checks every response, through {@code paztport-http}'s
 * {@link HttpCaller} in its blocking binding: the receiver's policy name, the binding over the raw target, the
 * response check and what a response adds to the request's influence are all the caller's. This adapts it to
 * Spring: it sets the headers the caller gives on the request as it goes on the wire, and hands the caller the
 * response read whole.
 *
 * <p>The body is read whole because the attestation covers all of it, and handed back from memory, so the
 * application reads exactly what was checked. Influence is recorded only inside a {@link RequestContext.Scope},
 * which the inbound filter opens per request; outside one a call is still stamped and its response still checked
 * and traced, but nothing is recorded.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private final HttpCaller caller;

    public OutboundInterceptor(HttpCaller caller) {
        this.caller = caller;
    }

    /**
     * A caller that names each receiver by its URI host. {@code verifier} is null where responses cannot be checked;
     * {@code caller} is this service's name.
     */
    public OutboundInterceptor(StamperV3 stamper, ProofBundle bundle, VerifierV3 verifier, String caller) {
        this(HttpCaller.builder(caller, stamper).bundle(bundle).verifier(verifier).build());
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        HttpCaller.Outbound sent = caller.stampFromContext(request.getMethod().name(), request.getURI(), body);
        sent.headers().forEach(request.getHeaders()::set);

        ClientHttpResponse response = execution.execute(request, body);
        Buffered buffered;
        try {
            // The status first: HttpURLConnection (Spring's simple request factory) hands over an error response's
            // body only once its status has been read, and otherwise throws on every 4xx and 5xx. The JDK client
            // the starter uses has no such order, but an application may give the builder either.
            response.getStatusCode();
            InputStream in = response.getBody();
            buffered = new Buffered(response, in == null ? new byte[0] : in.readAllBytes());
        } catch (IOException e) {
            response.close();
            throw e;
        }
        try {
            caller.recordToContext(sent, buffered.getStatusCode().value(),
                    buffered.getHeaders().getFirst(PaztportHeaders.RESPONSE), buffered.body);
        } catch (IOException | RuntimeException e) {
            buffered.close();
            throw e;
        }
        return buffered;
    }

    /** The response, with its body already read into memory, so the caller reads exactly what was checked. */
    private static final class Buffered implements ClientHttpResponse {
        private final ClientHttpResponse delegate;
        private final byte[] body;

        Buffered(ClientHttpResponse delegate, byte[] body) {
            this.delegate = delegate;
            this.body = body;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return delegate.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return delegate.getStatusText();
        }

        @Override
        public HttpHeaders getHeaders() {
            return delegate.getHeaders();
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
