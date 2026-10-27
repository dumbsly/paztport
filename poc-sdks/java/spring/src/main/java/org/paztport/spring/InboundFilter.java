// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.paztport.core.PathChainV1;
import org.paztport.core.VerifyResult;
import org.paztport.core.VerifierV1;
import org.paztport.http.HttpVerifyRequestsV1;
import org.paztport.http.PaztportHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Inbound half of the glue. Caches the body, stores the received chain in
 * {@link PaztportContext} for outbound appends, and — on a verifying service —
 * applies the current {@link VerificationMode}:
 *
 * <ul>
 *   <li>{@code OFF} — skip verification, pass through.</li>
 *   <li>{@code AUDIT} — verify, publish an event on failure, always pass through.</li>
 *   <li>{@code ENFORCE} — verify, publish an event and return 403 on failure.</li>
 * </ul>
 *
 * A null verifier skips verification on non-verifying hops. A non-null
 * {@link ReceivedRequestListener} is offered every request first, before any
 * verification, so an application can observe traffic without the SDK knowing why.
 */
public final class InboundFilter extends OncePerRequestFilter {

    private final VerifierV1 verifier;
    private final String receiver;
    private final ModeHolder modeHolder;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;

    public InboundFilter(
            VerifierV1 verifier, String receiver, ModeHolder modeHolder, EventPublisher publisher,
            ReceivedRequestListener listener) {
        this.verifier = verifier;
        this.receiver = receiver;
        this.modeHolder = modeHolder;
        this.publisher = publisher;
        this.listener = listener;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Control-plane endpoints are not part of the attested data path.
        String path = request.getRequestURI();
        return path.startsWith("/admin") || path.startsWith("/debug") || path.startsWith("/actuator");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = CachedBodyHttpServletRequest.readAll(request);
        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(request, body);

        String chainHeader = request.getHeader(PaztportHeaders.CHAIN);
        String proofHeader = request.getHeader(PaztportHeaders.PROOF);

        setContextFromChain(chainHeader);
        try {
            if (listener != null) {
                listener.received(chainHeader, proofHeader, request.getMethod(), request.getRequestURI(), body);
            }
            if (verifier != null && modeHolder.get() != VerificationMode.OFF) {
                VerificationMode mode = modeHolder.get();
                VerifyResult result = verifier.verify(
                        HttpVerifyRequestsV1.of(
                                chainHeader, proofHeader, request.getMethod(), request.getRequestURI(), body, receiver));
                if (!result.ok()) {
                    publisher.publish(new AttestationEvent(
                            result.reason().name(), result.suspectSvc(), result.suspectInst(),
                            currentRid(), mode == VerificationMode.AUDIT));
                    if (mode == VerificationMode.ENFORCE) {
                        reject(response, result);
                        return;
                    }
                }
            }
            chain.doFilter(wrapped, response);
        } finally {
            PaztportContext.clear();
        }
    }

    private static void setContextFromChain(String chainHeader) {
        if (chainHeader == null || chainHeader.isBlank()) {
            return;
        }
        try {
            PaztportContext.setInboundChain(PathChainV1.decode(chainHeader));
        } catch (RuntimeException e) {
            PaztportContext.setInboundChain(null);
        }
    }

    private static String currentRid() {
        PathChainV1 chain = PaztportContext.inboundChain();
        return (chain != null && !chain.stamps().isEmpty()) ? chain.stamps().get(0).rid() : "";
    }

    private static void reject(HttpServletResponse response, VerifyResult result) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write(String.format(
                "{\"reason\":\"%s\",\"suspectSvc\":\"%s\",\"suspectInst\":\"%s\"}",
                result.reason(), result.suspectSvc(), result.suspectInst()));
    }
}
