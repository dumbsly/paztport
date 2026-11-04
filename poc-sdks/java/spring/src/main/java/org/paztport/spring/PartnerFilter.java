// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import org.paztport.http.HttpSessions;
import org.paztport.http.InboundRequest;
import org.paztport.http.PartnerAccepted;
import org.paztport.http.PartnerReceiver;
import org.paztport.http.PartnerSessions;
import org.paztport.http.PeerCert;
import org.paztport.http.RequestContext;
import org.paztport.spring.internal.ObservedValues;
import org.paztport.spring.internal.PeerIdentity;
import org.paztport.spring.internal.Refusals;
import org.paztport.spring.internal.SessionStatus;
import org.paztport.spring.observation.PaztportObservation;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The partner's inbound filter, in place of {@link InboundFilter}: the servlet adapter over {@link PartnerReceiver},
 * which verifies another organisation's calls in the session the caller named, as its Javadoc says. It has no modes,
 * publishes no events and attests no responses.
 *
 * <p>This filter caches the body, hands the receiver the call and the client certificate the TLS layer
 * authenticated ({@link PeerIdentity}), through the request context
 * ({@link RequestContext#accept(PartnerReceiver, InboundRequest, PeerCert)}), which first ends any scope left open
 * on the thread and opens the call's own. It then either writes the receiver's refusal or serves the call in that
 * scope, which holds what the receiver decided: in an unsafe session, no influence and no verified chain, whatever
 * headers came; in an attested one, the verified influence, owners included, and the verified chain.
 * {@link org.paztport.spring.partner.PartnerGate} then refuses the operations switched off for unsafe sessions.
 *
 * <p>Every request gets {@link #SESSION_STATUS}, {@code attested} or {@code unsafe}, for the gate; a refused one is
 * marked unsafe, so nothing downstream could take it for attested.
 *
 * <p>Each call filtered is recorded as one {@link PaztportObservation#PARTNER_REQUEST} observation: the session it
 * named (attested, unsafe or unknown), the reason the session's verification gave and whether the call was served or
 * refused. It spans the decision and ends before the handler runs, with its error if the decision throws. Nothing
 * from the call is tagged, only fixed words and reason codes' names.
 *
 * <p>The handshake endpoint and the control plane are not filtered. A handler under those paths therefore runs
 * outside any scope, with no influence and no verified chain, and the gate counts it as unsafe.
 */
public final class PartnerFilter extends OncePerRequestFilter {

    /** The request attribute holding the session's status, {@code attested} or {@code unsafe}. */
    public static final String SESSION_STATUS = "org.paztport.spring.partner.session";

    private final PartnerReceiver receiver;
    private final ObservationRegistry observations;

    /**
     * @param sessions the sessions this partner has opened
     * @param receiver this service's name, the partner's entry: every boundary stamp must be addressed to it
     * @param observations where each call's verification result is recorded; {@link ObservationRegistry#NOOP} where
     *     the application has no {@code ObservationRegistry} bean
     */
    PartnerFilter(PartnerSessions sessions, String receiver, ObservationRegistry observations) {
        this.receiver = new PartnerReceiver(sessions, receiver);
        this.observations = Objects.requireNonNull(observations, "observations");
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
        try (RequestContext.Entered<PartnerAccepted> entered = observed(InboundFilter.inbound(request, body),
                PeerIdentity.cert(request))) {
            PartnerAccepted accepted = entered.result();
            if (accepted.refusal() != null) {
                Refusals.write(response, accepted.refusal());
                return;
            }
            if (accepted.attested()) {
                request.setAttribute(SESSION_STATUS, SessionStatus.ATTESTED);
            }
            chain.doFilter(wrapped, response);
        }
    }

    /**
     * The receiver's decision, as {@link RequestContext#accept(PartnerReceiver, InboundRequest, PeerCert)} makes it,
     * recorded as an observation that is open while the decision runs and stopped before this returns, so before the
     * handler. Every tag is known only once it is made. If an observation handler throws once the decision is made,
     * as its scope closes or as it stops, the call's scope is ended before the exception goes on, since nothing else
     * would close it and in an attested session it holds the verified chain and influence.
     */
    private RequestContext.Entered<PartnerAccepted> observed(InboundRequest inbound, PeerCert peer) {
        Observation observation = Observation
                .createNotStarted(PaztportObservation.PARTNER_REQUEST.getName(), observations).start();
        String session = ObservedValues.UNKNOWN;
        String reason = ObservedValues.NONE;
        String outcome = ObservedValues.REFUSED;
        RequestContext.Entered<PartnerAccepted> entered = null;
        try {
            try (Observation.Scope open = observation.openScope()) {
                entered = RequestContext.accept(receiver, inbound, peer);
                PartnerAccepted accepted = entered.result();
                session = accepted.result() != null ? ObservedValues.ATTESTED
                        : accepted.refusal() != null ? ObservedValues.UNKNOWN : ObservedValues.UNSAFE;
                reason = ObservedValues.reason(accepted.result());
                outcome = accepted.refusal() == null ? ObservedValues.SERVED : ObservedValues.REFUSED;
            } catch (Throwable t) {
                observation.error(t);
                throw t;
            } finally {
                observation.lowCardinalityKeyValue(PaztportObservation.Keys.SESSION.withValue(session))
                        .lowCardinalityKeyValue(PaztportObservation.Keys.REASON.withValue(reason))
                        .lowCardinalityKeyValue(PaztportObservation.Keys.OUTCOME.withValue(outcome))
                        .stop();
            }
            return entered;
        } catch (Throwable t) {
            if (entered != null) {
                entered.close();
            }
            throw t;
        }
    }
}
