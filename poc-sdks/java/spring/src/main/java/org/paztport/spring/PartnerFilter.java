// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.paztport.http.HttpSessions;
import org.paztport.http.PartnerAccepted;
import org.paztport.http.PartnerReceiver;
import org.paztport.http.PartnerSessions;
import org.paztport.http.RequestContext;
import org.paztport.spring.internal.PeerIdentity;
import org.paztport.spring.internal.SessionStatus;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The partner's inbound filter, in place of {@link InboundFilter}: the servlet adapter over {@link PartnerReceiver},
 * which verifies another organisation's calls in the session the caller named, as its Javadoc says. It has no modes,
 * publishes no events and attests no responses.
 *
 * <p>This filter caches the body, hands the receiver the call and the client certificate the TLS layer
 * authenticated ({@link PeerIdentity}), and then either writes the receiver's refusal or serves the call inside a
 * {@link RequestContext.Scope} holding what the receiver decided ({@link RequestContext#enter(PartnerAccepted)}):
 * in an unsafe session, no influence and no verified chain, whatever headers came; in an attested one, the verified
 * influence, owners included, and the verified chain. {@link org.paztport.spring.partner.PartnerGate} then refuses
 * the operations switched off for unsafe sessions.
 *
 * <p>Every request gets {@link #SESSION_STATUS}, {@code attested} or {@code unsafe}, for the gate; a refused one is
 * marked unsafe, so nothing downstream could take it for attested.
 *
 * <p>The handshake endpoint and the control plane are not filtered. A handler under those paths therefore runs
 * outside any scope, with no influence and no verified chain, and the gate counts it as unsafe.
 */
public final class PartnerFilter extends OncePerRequestFilter {

    /** The request attribute holding the session's status, {@code attested} or {@code unsafe}. */
    public static final String SESSION_STATUS = "org.paztport.spring.partner.session";

    private final PartnerReceiver receiver;

    /**
     * @param sessions the sessions this partner has opened
     * @param receiver this service's name, the partner's entry: every boundary stamp must be addressed to it
     */
    PartnerFilter(PartnerSessions sessions, String receiver) {
        this.receiver = new PartnerReceiver(sessions, receiver);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return InboundFilter.controlPlane(path) || path.equals(HttpSessions.PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = CachedBodyHttpServletRequest.readAll(request);
        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(request, body);
        // Marked unsafe until the request has verified, so a refusal is never taken for attested.
        request.setAttribute(SESSION_STATUS, SessionStatus.UNSAFE);
        PartnerAccepted accepted = receiver.accept(InboundFilter.inbound(request, body), PeerIdentity.cert(request));
        if (accepted.refusal() != null) {
            InboundFilter.refuse(response, accepted.refusal());
            return;
        }
        try (RequestContext.Scope scope = RequestContext.enter(accepted)) {
            if (accepted.attested()) {
                request.setAttribute(SESSION_STATUS, SessionStatus.ATTESTED);
            }
            chain.doFilter(wrapped, response);
        }
    }
}
