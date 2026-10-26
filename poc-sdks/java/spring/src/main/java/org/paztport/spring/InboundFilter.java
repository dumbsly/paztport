// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.paztport.core.PathChain;
import org.paztport.core.VerifyRequest;
import org.paztport.core.VerifyResult;
import org.paztport.core.Verifier;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Inbound half of the glue. Caches the body, stores the received chain in
 * {@link PathAttestContext} for outbound appends, and — on a verifying service —
 * applies the current {@link VerificationMode}:
 *
 * <ul>
 *   <li>{@code OFF} — skip verification, pass through.</li>
 *   <li>{@code AUDIT} — verify, publish an event on failure, always pass through.</li>
 *   <li>{@code ENFORCE} — verify, publish an event and return 403 on failure.</li>
 * </ul>
 *
 * A null verifier makes this a capture-only filter for non-verifying hops.
 */
public final class InboundFilter extends OncePerRequestFilter {

    private final Verifier verifier;
    private final ModeHolder modeHolder;
    private final EventPublisher publisher;
    private final CaptureStore captureStore;

    public InboundFilter(Verifier verifier, ModeHolder modeHolder, EventPublisher publisher, CaptureStore captureStore) {
        this.verifier = verifier;
        this.modeHolder = modeHolder;
        this.publisher = publisher;
        this.captureStore = captureStore;
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

        String chainHeader = request.getHeader(PathAttestHeaders.CHAIN);
        String proofHeader = request.getHeader(PathAttestHeaders.PROOF);

        setContextFromChain(chainHeader);
        try {
            if (captureStore != null) {
                captureStore.record(new CapturedRequest(chainHeader, proofHeader,
                        request.getMethod(), request.getRequestURI(), body));
            }
            if (verifier != null && modeHolder.get() != VerificationMode.OFF) {
                VerificationMode mode = modeHolder.get();
                VerifyResult result = verifier.verify(
                        new VerifyRequest(chainHeader, proofHeader, request.getMethod(), request.getRequestURI(), body));
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
            PathAttestContext.clear();
        }
    }

    private static void setContextFromChain(String chainHeader) {
        if (chainHeader == null || chainHeader.isBlank()) {
            return;
        }
        try {
            PathAttestContext.setInboundChain(PathChain.decode(chainHeader));
        } catch (RuntimeException e) {
            PathAttestContext.setInboundChain(null);
        }
    }

    private static String currentRid() {
        PathChain chain = PathAttestContext.inboundChain();
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
