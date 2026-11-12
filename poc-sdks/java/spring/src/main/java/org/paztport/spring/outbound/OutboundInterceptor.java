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
import java.util.Optional;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Verifier;
import org.paztport.http.HttpCaller;
import org.paztport.http.RequestContext;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.internal.Observed;
import org.paztport.spring.internal.ObservedValues;
import org.paztport.spring.observation.PaztportObservation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 *
 * <p>Given an {@link UnconnectedRetry}, a call that failed before its connection was established is sent once more,
 * at once, freshly stamped: a connect that timed out, a connect refused after the JDK client's own retry, or a TLS
 * handshake that failed. The JDK client writes no byte of a request before its connection, handshake included, is
 * established, so the first attempt reached no receiver, and the retry is the only delivery. The retry is stamped
 * again because a stamp's age runs from its signing; the delivery is the same, since replay protection and
 * idempotency key on the request tree, the caller, the receiver and the binding, not on the stamp. Its response is
 * checked against the second stamp. Nothing else is retried: a pooled connection the peer has closed, a reset after
 * the request was written and a read timeout may each have reached the receiver, so sending the call again could
 * deliver it twice; they surface as they are. There is one retry and no backoff, since a connect to a backend being
 * rolled succeeds on the next endpoint or not at all, and a wait would spend the window. If the retry fails too, its
 * exception surfaces with the first one added as suppressed.
 *
 * <p>Re-stamping does not make the origin's stamp any younger, so a retry could arrive after the origin's window and
 * fail its receiver's check as {@code EXPIRED}, a refusal under {@code enforce}, in place of the connect failure. So
 * inside a request the call is not retried when the origin's stamp, plus a whole connect timeout, would be past this
 * service's own origin window ({@code paztport.run-max-age-ms}, else {@code paztport.max-age-ms}), which stands in
 * for its receiver's; the connect failure surfaces instead. Outside a request, or at the origin, the retry's stamp is
 * the origin's, signed afresh, and is always sent. Each decision is counted as a {@code paztport.outbound.retry}
 * observation tagged with the failure and {@code retried} or {@code skipped}, and logged as one
 * {@code PAZTPORT_TRACE retry} line naming the request id, the receiver, the failure and the outcome.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final HttpCaller caller;
    private final ObservationRegistry observations;
    private final UnconnectedRetry retry;

    /** As {@link #OutboundInterceptor(HttpCaller, ObservationRegistry, UnconnectedRetry)}, never retrying. */
    public OutboundInterceptor(HttpCaller caller, ObservationRegistry observations) {
        this(caller, observations, null);
    }

    /**
     * @param observations where each response check and each retry decision is recorded;
     *     {@link ObservationRegistry#NOOP} where the application has no {@code ObservationRegistry} bean
     * @param retry how a call that never connected is retried; null for never
     */
    public OutboundInterceptor(HttpCaller caller, ObservationRegistry observations, UnconnectedRetry retry) {
        this.caller = caller;
        this.observations = Objects.requireNonNull(observations, "observations");
        this.retry = retry;
    }

    /**
     * A caller that names each receiver by its URI host, never retrying. {@code verifier} is null where responses
     * cannot be checked; {@code caller} is this service's name.
     */
    public OutboundInterceptor(Stamper stamper, ProofBundle bundle, Verifier verifier, String caller,
            ObservationRegistry observations) {
        this(HttpCaller.builder(caller, stamper).bundle(bundle).verifier(verifier).build(), observations);
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        HttpCaller.Outbound sent = stamped(request, body);
        ClientHttpResponse response;
        try {
            response = execution.execute(request, body);
        } catch (IOException first) {
            Optional<UnconnectedRetry.Failure> failure = retry == null ? Optional.empty()
                    : UnconnectedRetry.classify(first);
            if (failure.isEmpty()) {
                throw first;
            }
            if (retry.hopeless(originTs())) {
                decided(sent, failure.get(), ObservedValues.SKIPPED, first);
                throw first;
            }
            decided(sent, failure.get(), ObservedValues.RETRIED, first);
            try {
                sent = stamped(request, body);
                response = execution.execute(request, body);
            } catch (Throwable second) {
                second.addSuppressed(first);
                throw second;
            }
        }
        Buffered buffered;
        try {
            // The status first: HttpURLConnection (Spring's simple request factory) hands over an error response's
            // body only once its status has been read, and otherwise throws on every 4xx and 5xx. The JDK client
            // the starter uses has no such order, but an application may give the builder either.
            response.getStatusCode();
            InputStream in = response.getBody();
            buffered = new Buffered(response, in == null ? new byte[0] : in.readAllBytes());
        } catch (Throwable t) {
            // Whatever is thrown, the response is not handed on, so nothing else would release its connection.
            response.close();
            throw t;
        }
        try {
            observed(sent, buffered);
        } catch (Throwable t) {
            buffered.close();
            throw t;
        }
        return buffered;
    }

    /**
     * Stamps the call, from the context, and sets the stamp's headers on the request in place of every Paztport
     * header it carries.
     */
    private HttpCaller.Outbound stamped(HttpRequest request, byte[] body) {
        HttpCaller.Outbound sent = caller.stampFromContext(request.getMethod().name(), request.getURI(), body);
        HttpHeaders headers = request.getHeaders();
        for (String name : List.copyOf(headers.headerNames())) {
            if (PaztportHeaders.isPaztport(name)) {
                headers.remove(name);
            }
        }
        sent.headers().forEach(headers::set);
        return sent;
    }

    /**
     * When the origin signed the request this call is made for: the first stamp of the inbound chain, inside a
     * scope that holds one; otherwise null.
     */
    private static Long originTs() {
        if (!RequestContext.isOpen()) {
            return null;
        }
        List<Stamp> inbound = RequestContext.inboundChain();
        return inbound == null || inbound.isEmpty() ? null : inbound.get(0).ts();
    }

    /**
     * Records a decision on the call that failed with {@code first}, as a trace line and an observation. An
     * observation handler that throws is added to {@code first} as suppressed and {@code first} goes on, so the call
     * fails with its connect failure and is not retried.
     */
    private void decided(HttpCaller.Outbound sent, UnconnectedRetry.Failure failure, String outcome, IOException first)
            throws IOException {
        if (TRACE.isInfoEnabled()) {
            TRACE.info("PAZTPORT_TRACE retry rid={} receiver={} failure={} outcome={}",
                    LogSafe.of(sent.sent().chain().get(0).rid()), LogSafe.of(sent.receiver()), failure.tag(),
                    outcome);
        }
        try {
            Observation.createNotStarted(PaztportObservation.OUTBOUND_RETRY.getName(), observations)
                    .lowCardinalityKeyValue(PaztportObservation.Keys.FAILURE.withValue(failure.tag()))
                    .lowCardinalityKeyValue(PaztportObservation.Keys.OUTCOME.withValue(outcome))
                    .start().stop();
        } catch (RuntimeException | Error handler) {
            first.addSuppressed(handler);
            throw first;
        }
    }

    /**
     * The caller's check of {@code buffered}, as {@link HttpCaller#recordToContext} makes it, recorded as an
     * observation that is open while the check runs and stopped before this returns. The reason is known only once
     * the check is made, and stays {@code none} if it throws. One observation handler that throws as it records the
     * check's exception, or as it stops while that exception, or its scope's, is going on, is added to it as
     * suppressed, so the first exception is the one that goes on.
     */
    private void observed(HttpCaller.Outbound sent, Buffered buffered) throws IOException {
        Observation observation = Observation.createNotStarted(PaztportObservation.RESPONSE.getName(), observations)
                .start();
        Observed.<HttpWire.ResponseCheck, IOException>run(observation,
                held -> caller.recordToContext(sent, buffered.getStatusCode().value(),
                        buffered.getHeaders().getFirst(PaztportHeaders.RESPONSE), buffered.body),
                (stopping, check) -> stopping.lowCardinalityKeyValue(PaztportObservation.Keys.REASON.withValue(
                        check == null ? ObservedValues.NONE : ObservedValues.reason(check.result()))),
                check -> { });
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
