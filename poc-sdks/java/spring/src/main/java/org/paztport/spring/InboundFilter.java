// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.Accepted;
import org.paztport.http.HttpAnswer;
import org.paztport.http.HttpReceiver;
import org.paztport.http.InboundRequest;
import org.paztport.http.ModeHolder;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.ReceivedRequestListener;
import org.paztport.http.RequestContext;
import org.paztport.http.VerificationMode;
import org.paztport.http.event.EventPublisher;
import org.paztport.spring.internal.PeerIdentity;
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
 * <p>The control plane ({@link #controlPlane}) is not filtered.
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
     */
    public InboundFilter(
            VerifierV3 verifier, boolean verifyRequests, boolean origin, String receiver, ModeHolder modeHolder,
            EventPublisher publisher, ReceivedRequestListener listener, StamperV3 stamper) {
        if (verifyRequests && (verifier == null || modeHolder == null || publisher == null)) {
            throw new IllegalArgumentException("verifying requests needs a verifier, a mode holder and a publisher");
        }
        this.receiver = HttpReceiver.builder(receiver).verifier(verifier).verifyRequests(verifyRequests)
                .origin(origin).publisher(publisher).listener(listener).stamper(stamper).build();
        this.verifyRequests = verifyRequests;
        this.modeHolder = modeHolder;
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
        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(receiver, inbound(request, body),
                PeerIdentity.from(request), mode)) {
            Accepted accepted = entered.result();
            if (accepted.refusal() != null) {
                refuse(response, accepted.refusal());
                return;
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
            // Committed means the container has sent something the handler did not finish with: leave it alone.
            if (!cached.isCommitted()) {
                String attestation = accepted.attest(cached.getStatus(), cached.getContentAsByteArray(),
                        RequestContext.labels());
                if (attestation != null) {
                    cached.setHeader(PaztportHeaders.RESPONSE, attestation);
                }
            }
            cached.copyBodyToResponse();
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

    /** The request as a receiver reads it: the method, the raw target, the Paztport headers and the cached body. */
    static InboundRequest inbound(HttpServletRequest request, byte[] body) {
        Map<String, String> headers = new HashMap<>();
        for (String name : RECEIVED) {
            String value = request.getHeader(name);
            if (value != null) {
                headers.put(name, value);
            }
        }
        return new InboundRequest(request.getMethod(), target(request), headers, body);
    }

    /** The raw path, plus {@code ?} and the raw query when there is one: what the caller's binding covers. */
    static String target(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null || query.isEmpty() ? request.getRequestURI() : request.getRequestURI() + "?" + query;
    }

    /**
     * Writes a receiver's refusal as JSON, before any handler runs. A 403 names its charset and a 400 does not, as
     * each always has; both bodies are ASCII, so either reads the same.
     */
    static void refuse(HttpServletResponse response, HttpAnswer refusal) throws IOException {
        response.setStatus(refusal.status());
        response.setContentType("application/json");
        if (refusal.status() == HttpServletResponse.SC_FORBIDDEN) {
            response.setCharacterEncoding("UTF-8");
        }
        response.getWriter().write(new String(refusal.json(), StandardCharsets.UTF_8));
    }
}
