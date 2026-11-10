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
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
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
import org.paztport.spring.internal.Observed;
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
 * {@link Accepted#attest}, setting what comes back as {@code X-Path-Response}. Where a forward carries the request
 * elsewhere, the answer is finished when the forward returns, since the container closes the response then and drops
 * anything written to it later: it is attested where it may be if the forward wrote into this filter's buffer directly,
 * and never behind another filter's response wrapper. Behind a wrapper that does not buffer the body it arrives whole;
 * behind one that buffers it ({@code ShallowEtagHeaderFilter}, a logging {@code ContentCachingResponseWrapper}) it is
 * lost, as the container has closed the response before that filter copies it. Deciding when the answer is complete is
 * the servlet's part, and this filter's: a handler that throws sends no attestation, and a body the container writes
 * afterwards (an error page after {@code sendError}) is not the one attested; either way the caller cannot verify it
 * and counts it as untrusted. An async response is not attested either, because its body is written after the filter
 * has returned: it is sent whole when the async work completes, without {@code X-Path-Response}, and its caller counts
 * it as untrusted.
 *
 * <p>Each request filtered is recorded as one {@link PaztportObservation#REQUEST} observation: the mode, the reason
 * the verification gave and whether the request was served or refused. It spans the decision and ends before the
 * handler runs, with its error if the decision throws. Nothing from the request is tagged, only fixed words and
 * reason codes' names.
 *
 * <p>On a service that names its operations, the filter hands the receiver the operation the request will be
 * dispatched to, which {@link OperationResolver} works out from Spring's handler mappings before the receiver
 * verifies and before the handler runs. A chain naming another operation is then refused {@code BINDING_MISMATCH}.
 * The receiver holds the service's own table too, so where that operation declares a key it reads the key value from
 * the raw request target: a chain naming it is verified with the key value in its nonce key, and one whose target
 * gives none (a percent-encoded segment Spring decoded to reach the handler, say) is refused {@code BINDING_MISMATCH}.
 * Where the chain named an operation and the receiver verified the request with it, under a mode or for attestation
 * alone, the filter records that operation and its key value on the request's own dispatch
 * ({@link VerifiedOperation}), and the dispatch check reads them as the first handler the request reaches is about
 * to run.
 *
 * <p>Apart from the cases above, in which nothing is attested (a handler that throws, a forward behind another
 * filter's wrapper, an async response), an answer is attested only when:
 *
 * <ul>
 *   <li>the receiver attests it: the chain passed the live order here;</li>
 *   <li>the response is not committed when the answer is finished; and</li>
 *   <li>where the chain named an operation and the filter recorded it on the request's own dispatch, its handler was
 *       checked as it was about to run, was reached, and was not contradicted: it is the recorded operation and, for
 *       a keyed operation, reads the recorded key value.</li>
 * </ul>
 *
 * <p>The reasons:
 *
 * <ul>
 *   <li>A response stamp is shaped like a request stamp, so attesting a chain nobody checked would let whoever sent it
 *       mint stamps under this service's key ({@link HttpReceiver}).</li>
 *   <li>A committed response has gone out with what the container sent, which the handler did not finish with.</li>
 *   <li>Only the handler confirmed vouches for the operation. A later filter that changes the method, the path or the
 *       parameters, and so the handler or the item it acts on, by wrapping the request or by dispatching it
 *       elsewhere, is caught as the handler is about to run, which marks the record contradicted. An answer whose
 *       handler the check never saw (one a filter wrote itself, or another registered servlet's) is not the
 *       operation's, nor is one an interceptor wrote when it stopped the request before the handler was reached:
 *       Paztport's last interceptor records that it was.</li>
 * </ul>
 *
 * <p>A chain that names no operation is still attested, there being no operation to vouch for. So is the answer to a
 * forward this filter verifies afresh, one an unverified path's handler starts: the filter records no operation there,
 * so that answer is attested when its chain passes, with no dispatch check. A handler reached by an include cannot set
 * the status, so where the check refuses one, this filter writes the refusal once the chain returns, in place of
 * anything written before it, unless the response is already committed.
 *
 * <p>A path listed in {@code paztport.unverified-paths} ({@link #unverified}) is not filtered, so it is not observed.
 * None is listed unless the application lists it.
 */
public final class InboundFilter extends OncePerRequestFilter {

    /** The headers a receiver reads, which are the only ones it is handed. */
    private static final List<String> RECEIVED = List.of(PaztportHeaders.CHAIN, PaztportHeaders.PROOF,
            PaztportHeaders.INFLUENCE, PaztportHeaders.SESSION);

    /** The request attribute holding the answer this filter holds for attestation until it is finished. */
    private static final String PENDING = InboundFilter.class.getName() + ".pending";

    private final HttpReceiver receiver;
    private final boolean verifyRequests;
    private final ModeHolder modeHolder;
    private final OperationResolver operations;
    private final ObservationRegistry observations;
    private final List<String> unverifiedPaths;

    /**
     * @param verifier this service's verifier, or null where it holds no keyring, root and pin; without one it
     *     neither verifies nor attests
     * @param verifyRequests true where requests are verified under the mode ({@code paztport.verify=true}); it
     *     needs a verifier, a mode holder and a publisher, and under {@code OFF} it neither verifies nor attests.
     *     Otherwise the verifier only decides attestation.
     * @param origin true for an entry point ({@code paztport.origin=true}), which ignores the inbound chain and
     *     influence and never attests
     * @param receiver this service's name
     * @param modeHolder where the current {@link VerificationMode} is read, once per request; needed where
     *     {@code verifyRequests}, otherwise unused and may be null
     * @param publisher where the event for each request that fails verification under a mode goes; needed where
     *     {@code verifyRequests}, otherwise unused and may be null, since a failure that only withholds the
     *     attestation is not reported
     * @param listener offered every request before any verification ({@link ReceivedRequestListener}), or null for
     *     none
     * @param stamper this service's stamper, or null where it has no stamp key and so cannot attest
     * @param operations what tells each request's operation, and holds this service's own table for a keyed
     *     operation's key value, or null where this service names none; a chain that names an operation is then
     *     verified under the bare name, and so refused
     * @param observations where each request's verification result is recorded; {@link ObservationRegistry#NOOP}
     *     where the application has no {@code ObservationRegistry} bean
     * @param unverifiedPaths the path prefixes ({@code paztport.unverified-paths}) that are neither verified nor
     *     attested, each a first path segment starting with {@code /}; empty where every path is verified
     */
    InboundFilter(
            Verifier verifier, boolean verifyRequests, boolean origin, String receiver, ModeHolder modeHolder,
            EventPublisher publisher, ReceivedRequestListener listener, Stamper stamper,
            OperationResolver operations, ObservationRegistry observations,
            List<String> unverifiedPaths) {
        if (verifyRequests && (verifier == null || modeHolder == null || publisher == null)) {
            throw new IllegalArgumentException("verifying requests needs a verifier, a mode holder and a publisher");
        }
        this.receiver = HttpReceiver.builder(receiver).verifier(verifier).verifyRequests(verifyRequests)
                .origin(origin).publisher(publisher).listener(listener).stamper(stamper)
                .operations(operations == null ? null : operations.table()).build();
        this.verifyRequests = verifyRequests;
        this.modeHolder = modeHolder;
        this.operations = operations;
        this.observations = Objects.requireNonNull(observations, "observations");
        this.unverifiedPaths = requireWellFormed(unverifiedPaths);
    }

    /**
     * Returns a copy of {@code paths} after checking that each is one first path segment: a slash and then letters,
     * digits or {@code . _ ~ -}, with no second slash, dot segment, semicolon, percent sign or backslash. An empty
     * entry, which Boot binds from a trailing comma, would leave every path unverified, and {@code /} would leave
     * {@code /} and {@code //x} so.
     *
     * @throws IllegalStateException naming {@code paztport.unverified-paths} and the first bad entry
     */
    static List<String> requireWellFormed(List<String> paths) {
        for (String entry : paths) {
            if (entry == null || !entry.matches("/[A-Za-z0-9._~-]+") || entry.equals("/.") || entry.equals("/..")) {
                throw new IllegalStateException("paztport.unverified-paths has the entry \"" + entry + "\", which is "
                        + "not one first path segment such as /actuator: a slash and then letters, digits or "
                        + ". _ ~ -, with no second slash, dot segment, semicolon, percent sign or backslash");
            }
        }
        return List.copyOf(paths);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return unverified(request.getRequestURI(), unverifiedPaths);
    }

    /**
     * Whether {@code path}, the raw request URI, is left unverified: one of {@code prefixes} as a whole first
     * segment, alone or followed by {@code /}, with no dot segment and no encoded or backslash separator anywhere in
     * it. Matched by segment, not by text, so that a data-path handler whose name only begins the same way, such as
     * {@code /administration} beside {@code /admin}, is still verified. A dot segment ({@link #dotSegment}) is never
     * skipped, since whatever resolves it, the container or a handler, could take {@code /admin/../pay} to a
     * data-path handler that would then run unverified; nor is {@code %2f}, {@code %5c} (in either case) or a literal
     * {@code \}, which something downstream might read as a separator and so as a dot segment's. Anything else is
     * verified, an encoded or doubled first segment ({@code /%61dmin}, {@code //admin}) and one with a path parameter
     * ({@code /admin;x}) included, which fails closed. The prefixes are well formed
     * ({@link #requireWellFormed}, which both filters apply to theirs), so none is empty.
     */
    static boolean unverified(String path, List<String> prefixes) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (path.indexOf('\\') >= 0 || lower.contains("%2f") || lower.contains("%5c")) {
            return false;
        }
        for (String prefix : prefixes) {
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
        // The handler the request will reach decides its operation, before the receiver verifies the chain. A service
        // routes by method, path and query alone, so the operation is named without the body's form fields; a body
        // field that makes Spring choose another handler is caught when that handler is about to run.
        String operation = operations == null ? null : operations.operationFor(wrapped.withQueryParametersOnly());
        try (RequestContext.Entered<Accepted> entered = observed(inbound(request, body, operation),
                PeerIdentity.from(request), mode)) {
            Accepted accepted = entered.result();
            if (accepted.refusal() != null) {
                Refusals.write(response, accepted.refusal());
                return;
            }
            VerifiedOperation verified = null;
            if (accepted.operation() != null && request.getDispatcherType() == DispatcherType.REQUEST) {
                // Read as the handler is about to run, which catches a later filter that changes the handler or item.
                // Recorded only on the request's own dispatch, before any handler has run, so the handler checked is
                // the first the request reaches. A forward this filter verifies afresh, because it skipped the
                // request's own dispatch (an unverified path whose handler forwards), records none: its handler is
                // not checked, and its answer is attested when its chain passes.
                verified = new VerifiedOperation(accepted.operation(), accepted.key(),
                        mode == VerificationMode.ENFORCE);
                request.setAttribute(VerifiedOperation.ATTRIBUTE, verified);
            }
            if (!accepted.attests()) {
                chain.doFilter(wrapped, response);
                writeOwedRefusal(verified, response);
                return;
            }
            Pending pending = new Pending(accepted, verified, new ContentCachingResponseWrapper(response));
            // A forward finishes the answer when it returns (see doFilter); one the chain leaves unfinished, because
            // a handler threw, is never finished by a dispatch that comes later, such as the error page's.
            request.setAttribute(PENDING, pending);
            try {
                chain.doFilter(wrapped, pending.cached);
            } finally {
                request.removeAttribute(PENDING);
            }
            finish(request, pending, true);
        }
    }

    /**
     * Runs a forward dispatch that carries the request's held answer, and finishes that answer when the forward
     * returns; every other dispatch is filtered as {@link OncePerRequestFilter} decides.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getDispatcherType() == DispatcherType.FORWARD && request instanceof HttpServletRequest forwarded
                && request.getAttribute(PENDING) instanceof Pending pending && !pending.finished) {
            chain.doFilter(request, response);
            // The servlet spec closes the response when a forward returns, and Tomcat suspends it, so the answer is
            // final here and anything copied to it later would be dropped. A later filter may hold the forwarded
            // body in its own buffer and copy it only after this, so only a forward that writes straight into the
            // held wrapper can be vouched for; behind any other wrapper the answer is not attested.
            finish(forwarded, pending, response == pending.cached);
            return;
        }
        super.doFilter(request, response, chain);
    }

    /**
     * Finishes the held answer once: writes any refusal the check owes, then either leaves the body to async work
     * or sends it, attested where {@code attestable} and the rule below allow. Whichever dispatch finishes first,
     * the innermost forward or the request's own, does it; the others find it finished.
     */
    private static void finish(HttpServletRequest request, Pending pending, boolean attestable) throws IOException {
        if (pending.finished) {
            return;
        }
        pending.finished = true;
        ContentCachingResponseWrapper cached = pending.cached;
        VerifiedOperation verified = pending.verified;
        // Written before an async start returns, so an include a filter then follows with async work is refused.
        writeOwedRefusal(verified, cached);
        if (request.isAsyncStarted()) {
            // The handler returned before writing its body, so there is nothing yet to attest. The body is written
            // into the wrapper later, on another thread, and must still reach the caller whole.
            request.getAsyncContext().addListener(new CopyWhenComplete(cached));
            return;
        }
        // Committed means the container has sent something the handler did not finish with: leave it alone. Where
        // an operation was verified, an answer whose handler the check never saw, or found to be another
        // operation's, or that an interceptor wrote before the handler was reached, is not the confirmed
        // operation's, so it is not attested.
        if (attestable && !cached.isCommitted() && (verified == null
                || (verified.checked() && verified.reached() && !verified.contradicted()))) {
            String attestation = pending.accepted.attest(cached.getStatus(), cached.getContentAsByteArray(),
                    RequestContext.labels());
            if (attestation != null) {
                cached.setHeader(PaztportHeaders.RESPONSE, attestation);
            }
        }
        cached.copyBodyToResponse();
    }

    /**
     * Writes the refusal the check owes for a handler reached by an include ({@link VerifiedOperation#refusalOwed}),
     * which could not set the status itself, in place of anything a filter after this one wrote around the include.
     * A response already committed has gone out with what that filter sent and cannot be refused; its handler did
     * not run, and nothing is attested for it.
     */
    private static void writeOwedRefusal(VerifiedOperation verified, HttpServletResponse response)
            throws IOException {
        if (verified != null && verified.refusalOwed() && !response.isCommitted()) {
            response.resetBuffer();
            Refusals.write(response, VerifiedOperation.REFUSAL);
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
        return Observed.run(observation, held -> {
            RequestContext.Entered<Accepted> entered = RequestContext.accept(receiver, inbound, peer, mode);
            held.accept(entered);
            Accepted accepted = entered.result();
            if (accepted.cacheFailure() != null) {
                // The receiver has logged it; the observation carries it so the error is counted.
                observation.error(accepted.cacheFailure());
            }
            return entered;
        }, (stopping, entered) -> {
            Accepted accepted = entered == null ? null : entered.result();
            stopping.lowCardinalityKeyValue(PaztportObservation.Keys.REASON.withValue(
                            accepted == null ? ObservedValues.NONE : ObservedValues.reason(accepted.result())))
                    .lowCardinalityKeyValue(PaztportObservation.Keys.OUTCOME.withValue(
                            accepted != null && accepted.refusal() == null
                                    ? ObservedValues.SERVED : ObservedValues.REFUSED));
        }, RequestContext.Entered::close);
    }

    /**
     * An answer held for attestation until it is finished: the receiver's decision, the operation recorded for the
     * check or null, and the wrapper holding the body.
     */
    private static final class Pending {
        private final Accepted accepted;
        private final VerifiedOperation verified;
        private final ContentCachingResponseWrapper cached;
        private boolean finished;

        Pending(Accepted accepted, VerifiedOperation verified, ContentCachingResponseWrapper cached) {
            this.accepted = accepted;
            this.verified = verified;
            this.cached = cached;
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
