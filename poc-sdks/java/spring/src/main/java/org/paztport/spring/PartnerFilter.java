// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.HttpSessions;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.spring.internal.LogSafe;
import org.paztport.spring.internal.PeerIdentity;
import org.paztport.spring.internal.SessionStatus;
import org.paztport.spring.partner.PartnerSessions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The partner's inbound filter, in place of {@link InboundFilter}: another organisation's calls are verified in the
 * session the caller named, against the keyring and root it presented in that session's handshake, rather than
 * against this organisation's own. It has no modes, publishes no events and attests no responses.
 *
 * <p>The session is named by {@code X-Path-Session}, and is looked up for the peer the TLS layer authenticated, by
 * its certificate's issuer and common name:
 *
 * <ul>
 *   <li>No header means the caller never opened a session, which is treated as unsafe.</li>
 *   <li>A header that does not name a live session this peer opened is refused {@code 403 SESSION_UNKNOWN}: another
 *       peer's id (another name, or the same name under another issuer), an evicted or expired one, one from
 *       before a restart, or a caller with no certificate. It is never taken as unsafe, or a caller could step down
 *       from a session it was refused in by naming a wrong one.</li>
 *   <li>In an unsafe session nothing is verified, so nothing from the request is believed: the handler starts with
 *       no influence and no verified chain, whatever headers came, and
 *       {@link org.paztport.spring.partner.PartnerGate} refuses the operations switched off for such sessions.</li>
 *   <li>In an attested session the chain is verified in the live order by that session's own verifier, with this
 *       service as receiver and the peer as last signer, and a failure is refused {@code 403} with its code. Only
 *       on {@code OK} does the handler get the verified influence, owners included, and the verified chain.</li>
 * </ul>
 *
 * <p>Every request gets {@link #SESSION_STATUS}, {@code attested} or {@code unsafe}, for the gate; a refused one is
 * marked unsafe, so nothing downstream could take it for attested. Each logs one {@code PAZTPORT_TRACE request}
 * line naming its session's status.
 *
 * <p>The handshake endpoint and the control plane are not filtered. A handler under those paths therefore runs
 * outside any scope, with no influence and no verified chain, and the gate counts it as unsafe.
 */
public final class PartnerFilter extends OncePerRequestFilter {

    /** The request attribute holding the session's status, {@code attested} or {@code unsafe}. */
    public static final String SESSION_STATUS = "org.paztport.spring.partner.session";

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final PartnerSessions sessions;
    private final String receiver;

    /**
     * @param sessions the sessions this partner has opened
     * @param receiver this service's name, the partner's entry: every boundary stamp must be addressed to it
     */
    PartnerFilter(PartnerSessions sessions, String receiver) {
        this.sessions = sessions;
        this.receiver = receiver;
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

        String sessionHeader = request.getHeader(PaztportHeaders.SESSION);
        String chainHeader = request.getHeader(PaztportHeaders.CHAIN);
        Peer peer = PeerIdentity.from(request);
        // Only for the trace line: nothing is taken from a chain until it has verified.
        List<StampV3> received = InboundFilter.parseChain(chainHeader);
        String rid = received != null ? received.get(0).rid() : "";

        InboundFilter.endLeakedScope();
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            // Marked unsafe until the request has verified, so a refusal is never taken for attested.
            request.setAttribute(SESSION_STATUS, SessionStatus.UNSAFE);
            PartnerSessions.Session session = null;
            if (sessionHeader != null) {
                session = sessions.find(PeerIdentity.issuer(request), peer == null ? null : peer.svc(),
                        sessionHeader);
                if (session == null) {
                    VerifyResult unknown = new VerifyResult(ReasonCode.SESSION_UNKNOWN,
                            peer == null ? "" : peer.svc(), peer == null ? "" : peer.inst());
                    trace(InboundFilter.traceLine(rid, unknown, receiver, peer, null, "unknown"));
                    InboundFilter.reject(response, unknown);
                    return;
                }
            }
            if (session == null || !session.attested()) {
                trace(String.format("PAZTPORT_TRACE request rid=%s reason=- receiver=%s %s session=unsafe",
                        rid.isEmpty() ? "-" : LogSafe.of(rid), LogSafe.of(receiver), InboundFilter.peerField(peer)));
                chain.doFilter(wrapped, response);
                return;
            }

            VerifyInputV3 input = HttpV3.request(chainHeader, request.getHeader(PaztportHeaders.PROOF),
                    request.getHeader(PaztportHeaders.INFLUENCE), request.getMethod(), InboundFilter.target(request),
                    body, receiver, peer);
            VerifyResult result = session.verifier().verify(input);
            // On OK these are the entries the boundary stamp committed to; otherwise what was received.
            List<InfluenceEntry> influence = InboundFilter.parseInfluence(input.influence());
            trace(InboundFilter.traceLine(rid, result, receiver, peer, influence, SessionStatus.ATTESTED));
            if (!result.ok()) {
                InboundFilter.reject(response, result);
                return;
            }
            if (influence == null || received == null) {
                // Not reachable after OK; refused rather than served with less than was committed to.
                InboundFilter.unreadableInfluence(response);
                return;
            }
            PaztportContext.addInfluence(influence.toArray(InfluenceEntry[]::new));
            PaztportContext.setInboundChain(received);
            PaztportContext.markVerified(received);
            request.setAttribute(SESSION_STATUS, SessionStatus.ATTESTED);
            chain.doFilter(wrapped, response);
        }
    }

    private static void trace(String line) {
        if (TRACE.isInfoEnabled()) {
            TRACE.info(line);
        }
    }
}
