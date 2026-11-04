// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Verifier;
import org.paztport.http.HttpCaller;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.internal.ObservedValues;
import org.paztport.spring.observation.PaztportObservation;
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
 * application reads exactly what was checked. Each response check is recorded as a {@code paztport.response}
 * observation tagged with the check's reason code, or {@code none} where there is no verifier or the check threw; it
 * is open only while the caller records the response and stopped before this returns, with its error if that throws.
 * Nothing from the response is tagged. Influence is recorded only inside a {@link RequestContext.Scope},
 * which the inbound filter opens per request; outside one a call is still stamped and its response still checked
 * and traced, but nothing is recorded.
 *
 * <p>The request carries only the Paztport headers the caller stamped, as the spec's header rule says: any the
 * application set on the request before this interceptor runs are removed first.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private final HttpCaller caller;
    private final ObservationRegistry observations;

    /**
     * @param observations where each response check is recorded; {@link ObservationRegistry#NOOP} where the
     *     application has no {@code ObservationRegistry} bean
     */
    public OutboundInterceptor(HttpCaller caller, ObservationRegistry observations) {
        this.caller = caller;
        this.observations = Objects.requireNonNull(observations, "observations");
    }

    /**
     * A caller that names each receiver by its URI host. {@code verifier} is null where responses cannot be checked;
     * {@code caller} is this service's name.
     */
    public OutboundInterceptor(Stamper stamper, ProofBundle bundle, Verifier verifier, String caller,
            ObservationRegistry observations) {
        this(HttpCaller.builder(caller, stamper).bundle(bundle).verifier(verifier).build(), observations);
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        HttpCaller.Outbound sent = caller.stampFromContext(request.getMethod().name(), request.getURI(), body);
        HttpHeaders headers = request.getHeaders();
        for (String name : List.copyOf(headers.headerNames())) {
            if (PaztportHeaders.isPaztport(name)) {
                headers.remove(name);
            }
        }
        sent.headers().forEach(headers::set);

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
            observed(sent, buffered);
        } catch (IOException | RuntimeException e) {
            buffered.close();
            throw e;
        }
        return buffered;
    }

    /**
     * The caller's check of {@code buffered}, as {@link HttpCaller#recordToContext} makes it, recorded as an
     * observation that is open while the check runs and stopped before this returns. The reason is known only once
     * the check is made, and stays {@code none} if it throws.
     */
    private void observed(HttpCaller.Outbound sent, Buffered buffered) throws IOException {
        Observation observation = Observation.createNotStarted(PaztportObservation.RESPONSE.getName(), observations)
                .start();
        String reason = ObservedValues.NONE;
        try (Observation.Scope open = observation.openScope()) {
            HttpWire.ResponseCheck check = caller.recordToContext(sent, buffered.getStatusCode().value(),
                    buffered.getHeaders().getFirst(PaztportHeaders.RESPONSE), buffered.body);
            reason = check == null ? ObservedValues.NONE : ObservedValues.reason(check.result());
        } catch (Throwable t) {
            observation.error(t);
            throw t;
        } finally {
            observation.lowCardinalityKeyValue(PaztportObservation.Keys.REASON.withValue(reason)).stop();
        }
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
