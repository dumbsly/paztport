// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.Verifier;
import org.paztport.http.Accepted;
import org.paztport.http.HttpReceiver;
import org.paztport.http.InboundRequest;
import org.paztport.http.ModeHolder;
import org.paztport.http.ReceivedRequestListener;
import org.paztport.http.RequestContext;
import org.paztport.http.VerificationMode;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.spring.internal.ObservedValues;
import org.paztport.spring.internal.PeerIdentity;
import org.paztport.spring.internal.Refusals;
import org.paztport.spring.internal.VerifiedOperation;
import org.paztport.spring.observation.PaztportObservation;
import org.paztport.spring.operation.OperationResolver;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Inbound half of the glue: the servlet adapter over {@link HttpReceiver}, which decides each request (what is
 * refused, what the handler starts from, when the answer is attested) as its Javadoc says. This filter caches the
 * body, reads the current {@link VerificationMode} once per request on a service that verifies requests
 * ({@code paztport.verify=true}), hands the receiver the request and the peer the TLS handshake authenticated
 * ({@link PeerIdentity}). It runs the receiver through the request context
 * ({@link RequestContext#accept(HttpReceiver, InboundRequest, Peer, VerificationMode)}), which first ends any scope
 * left open on the thread and opens the request's own, so the listener and the publisher run in it too. It then
 * either writes the receiver's refusal or serves the request in that scope, which holds what the receiver decided,
 * so what its handler and its calls learn is carried for the request and dropped when it ends, refused or not. Async
 * work after the handler returns runs outside it.
 *
 * <p>When the receiver says the answer is attested, this filter holds the body until the handler returns, since the
 * stamp covers all of it, and hands the status, the body and the handler's labels ({@link RequestContext#label}) to
 * {@link Accepted#attest}, setting what comes back as {@code X-Path-Response}. Deciding when the answer is complete
 * is the servlet's part, and this filter's: a handler that throws sends no attestation, and a body the container
 * writes afterwards (an error page after {@code sendError}) is not the one attested; either way the caller cannot
 * verify it and counts it as untrusted. An async response is not attested either, because its body is written after
 * the filter has returned: it is sent whole when the async work completes, without {@code X-Path-Response}, and its
 * caller counts it as untrusted.
 *
 * <p>Each request filtered is recorded as one {@link PaztportObservation#REQUEST} observation: the mode, the reason
 * the verification gave and whether the request was served or refused. It spans the decision and ends before the
 * handler runs, with its error if the decision throws. Nothing from the request is tagged, only fixed words and
 * reason codes' names.
 *
 * <p>On a service that names its operations, the filter hands the receiver the operation the request will be
 * dispatched to, which {@link OperationResolver} works out from Spring's handler mappings before the receiver
 * verifies and before the handler runs. A chain naming another operation is then refused {@code BINDING_MISMATCH}.
 * Where the chain named an operation and the receiver verified the request with it, under a mode or for attestation
 * alone, the filter records that operation on the request ({@link VerifiedOperation}), so that a later filter which
 * changes the method or the path, and so the handler, by wrapping the request or by forwarding it, is caught as the
 * handler is about to run; the answer of a handler caught there is never attested.
 *
 * <p>The control plane ({@link #controlPlane}) is not filtered, so it is not observed.
 */
public final class InboundFilter extends OncePerRequestFilter {

    /** The first path segments of the control plane, which is not part of the attested data path. */
    private static final List<String> CONTROL_PLANE = List.of("/admin", "/debug", "/actuator");

    /** The headers a receiver reads, which are the only ones it is handed. */
    private static final List<String> RECEIVED = List.of(PaztportHeaders.CHAIN, PaztportHeaders.PROOF,
            PaztportHeaders.INFLUENCE, PaztportHeaders.SESSION);

    private final HttpReceiver receiver;
    private final boolean verifyRequests;
    private final ModeHolder modeHolder;
    private final OperationResolver operations;
    private final ObservationRegistry observations;

    /**
     * @param verifier this service's verifier, or null where it holds no keyring, root and pin; without one it
     *     neither verifies nor attests
     * @param verifyRequests true where requests are verified under the mode ({@code paztport.verify=true}); it
     *     needs a verifier, a mode holder and a publisher, and under {@code OFF} it neither verifies nor attests.
     *     Otherwise the verifier only decides attestation.
     * @param origin true for an entry point ({@code paztport.origin=true}), which ignores the inbound chain and
     *     influence and never attests
     * @param receiver this service's name
     * @param stamper this service's stamper, or null where it has no stamp key and so cannot attest
     * @param operations what tells each request's operation, or null where this service names none; a chain that
     *     names an operation is then verified under the bare name, and so refused
     * @param observations where each request's verification result is recorded; {@link ObservationRegistry#NOOP}
     *     where the application has no {@code ObservationRegistry} bean
     */
    public InboundFilter(
            Verifier verifier, boolean verifyRequests, boolean origin, String receiver, ModeHolder modeHolder,
            EventPublisher publisher, ReceivedRequestListener listener, Stamper stamper,
            OperationResolver operations, ObservationRegistry observations) {
        if (verifyRequests && (verifier == null || modeHolder == null || publisher == null)) {
            throw new IllegalArgumentException("verifying requests needs a verifier, a mode holder and a publisher");
        }
        this.receiver = HttpReceiver.builder(receiver).verifier(verifier).verifyRequests(verifyRequests)
                .origin(origin).publisher(publisher).listener(listener).stamper(stamper).build();
        this.verifyRequests = verifyRequests;
        this.modeHolder = modeHolder;
        this.operations = operations;
        this.observations = Objects.requireNonNull(observations, "observations");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return controlPlane(request.getRequestURI());
    }

    /**
     * Whether {@code path}, the raw request URI, is in the control plane: one of {@link #CONTROL_PLANE} as a whole
     * first segment, alone or followed by {@code /}, with no dot segment and no encoded or backslash separator
     * anywhere in it. Matched by segment, not by text, so that a data-path handler whose name only begins the same
     * way, such as {@code /administration}, is still verified. A dot segment ({@link #dotSegment}) is never skipped,
     * since whatever resolves it, the container or a handler, could take {@code /admin/../pay} to a data-path handler
     * that would then run unverified; nor is {@code %2f}, {@code %5c} (in either case) or a literal {@code \}, which
     * something downstream might read as a separator and so as a dot segment's. Anything else is verified, an encoded
     * or doubled first segment ({@code /%61dmin}, {@code //admin}) and one with a path parameter ({@code /admin;x})
     * included, which fails closed.
     */
    static boolean controlPlane(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (path.indexOf('\\') >= 0 || lower.contains("%2f") || lower.contains("%5c")) {
            return false;
        }
        for (String prefix : CONTROL_PLANE) {
            if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                for (String segment : path.split("/", -1)) {
                    if (dotSegment(segment)) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a raw path segment is {@code .} or {@code ..}: after dropping any {@code ;} parameter, and with each
     * {@code %2e}, in either case, read as the dot it encodes, since a container may decode either before it
     * resolves the path.
     */
    static boolean dotSegment(String segment) {
        int semicolon = segment.indexOf(';');
        String name = (semicolon < 0 ? segment : segment.substring(0, semicolon)).replaceAll("(?i)%2e", ".");
        return name.equals(".") || name.equals("..");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = CachedBodyHttpServletRequest.readAll(request);
        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(request, body);
        VerificationMode mode = verifyRequests ? modeHolder.get() : VerificationMode.OFF;
        // The handler the request will reach decides its operation, before the receiver verifies the chain.
        String operation = operations == null ? null : operations.operationFor(wrapped);
        try (RequestContext.Entered<Accepted> entered = observed(inbound(request, body, operation),
                PeerIdentity.from(request), mode)) {
            Accepted accepted = entered.result();
            if (accepted.refusal() != null) {
                Refusals.write(response, accepted.refusal());
                return;
            }
            VerifiedOperation verified = null;
            if (accepted.operation() != null && request.getDispatcherType() == DispatcherType.REQUEST) {
                // Read as the handler is about to run, which catches a later filter that changes the handler.
                verified = new VerifiedOperation(accepted.operation(), mode == VerificationMode.ENFORCE);
                request.setAttribute(VerifiedOperation.ATTRIBUTE, verified);
            }
            if (!accepted.attests()) {
                chain.doFilter(wrapped, response);
                return;
            }
            ContentCachingResponseWrapper cached = new ContentCachingResponseWrapper(response);
            chain.doFilter(wrapped, cached);
            if (request.isAsyncStarted()) {
                // The handler returned before writing its body, so there is nothing yet to attest. The body is
                // written into the wrapper later, on another thread, and must still reach the caller whole.
                request.getAsyncContext().addListener(new CopyWhenComplete(cached));
                return;
            }
            // Committed means the container has sent something the handler did not finish with: leave it alone. A
            // handler that is not the operation verified answered for another, so its answer is not attested.
            if (!cached.isCommitted() && (verified == null || !verified.contradicted())) {
                String attestation = accepted.attest(cached.getStatus(), cached.getContentAsByteArray(),
                        RequestContext.labels());
                if (attestation != null) {
                    cached.setHeader(PaztportHeaders.RESPONSE, attestation);
                }
            }
            cached.copyBodyToResponse();
        }
    }

    /**
     * The receiver's decision, as {@link RequestContext#accept(HttpReceiver, InboundRequest, Peer, VerificationMode)}
     * makes it, recorded as an observation that is open while the decision runs and stopped before this returns, so
     * before the handler. The mode is known at the start; the reason and the outcome only once it is made. If an
     * observation handler throws once the decision is made, as its scope closes or as it stops, the request's scope
     * is ended before the exception goes on, since nothing else would close it and it holds the chain verified here.
     * One that throws as it records the decision's exception, or as it stops while that exception, or its scope's,
     * is going on, is added to it as suppressed, so the first exception is the one that goes on.
     */
    private RequestContext.Entered<Accepted> observed(InboundRequest inbound, Peer peer, VerificationMode mode) {
        Observation observation = Observation.createNotStarted(PaztportObservation.REQUEST.getName(), observations)
                .lowCardinalityKeyValue(PaztportObservation.Keys.MODE.withValue(
                        verifyRequests ? mode.name().toLowerCase(Locale.ROOT) : ObservedValues.NONE))
                .start();
        String reason = ObservedValues.NONE;
        String outcome = ObservedValues.REFUSED;
        RequestContext.Entered<Accepted> entered = null;
        Throwable failure = null;
        try {
            try (Observation.Scope open = observation.openScope()) {
                entered = RequestContext.accept(receiver, inbound, peer, mode);
                Accepted accepted = entered.result();
                if (accepted.cacheFailure() != null) {
                    // The receiver has logged it; the observation carries it so the error is counted.
                    observation.error(accepted.cacheFailure());
                }
                reason = ObservedValues.reason(accepted.result());
                outcome = accepted.refusal() == null ? ObservedValues.SERVED : ObservedValues.REFUSED;
            } catch (Throwable t) {
                failure = t;
                try {
                    observation.error(t);
                } catch (Throwable erroring) {
                    if (erroring != t) {
                        t.addSuppressed(erroring);
                    }
                }
                throw t;
            } finally {
                try {
                    observation.lowCardinalityKeyValue(PaztportObservation.Keys.REASON.withValue(reason))
                            .lowCardinalityKeyValue(PaztportObservation.Keys.OUTCOME.withValue(outcome))
                            .stop();
                } catch (Throwable stopping) {
                    if (failure == null) {
                        throw stopping;
                    }
                    if (stopping != failure) {
                        failure.addSuppressed(stopping);
                    }
                }
            }
            return entered;
        } catch (Throwable t) {
            if (entered != null) {
                entered.close();
            }
            throw t;
        }
    }

    /** Sends an async response's body, held by the wrapper, once the async work has finished writing it. */
    private record CopyWhenComplete(ContentCachingResponseWrapper cached) implements AsyncListener {
        @Override
        public void onComplete(AsyncEvent event) throws IOException {
            cached.copyBodyToResponse();
        }

        @Override
        public void onTimeout(AsyncEvent event) {
        }

        @Override
        public void onError(AsyncEvent event) {
        }

        @Override
        public void onStartAsync(AsyncEvent event) {
        }
    }

    /**
     * The request as a receiver reads it: the method, the raw target, the Paztport headers, the cached body and the
     * operation it will be dispatched to, or null for none.
     */
    static InboundRequest inbound(HttpServletRequest request, byte[] body, String operation) {
        Map<String, String> headers = new HashMap<>();
        for (String name : RECEIVED) {
            String value = request.getHeader(name);
            if (value != null) {
                headers.put(name, value);
            }
        }
        return new InboundRequest(request.getMethod(), target(request), headers, body, operation);
    }

    /** The raw path, plus {@code ?} and the raw query when there is one: what the caller's binding covers. */
    static String target(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null || query.isEmpty() ? request.getRequestURI() : request.getRequestURI() + "?" + query;
    }
}
