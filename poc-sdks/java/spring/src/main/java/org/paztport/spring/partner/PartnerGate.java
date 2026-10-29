// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.paztport.core.verify.ReasonCode;
import org.paztport.spring.PartnerFilter;
import org.paztport.spring.PaztportContext;
import org.paztport.spring.internal.SessionStatus;
import org.paztport.spring.internal.TraceLines;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Refuses, in any session that is not attested, the operations the partner switched off for unsafe sessions:
 * {@code 403 {"reason":"UNSAFE_SESSION"}}, and the handler does not run.
 *
 * <p>An operation is {@code <METHOD> <route pattern>}, the pattern of the handler Spring actually dispatched to, not
 * the path the caller wrote. So {@code /refund;x=1} or {@code //refund}, which reach the {@code /refund} handler,
 * are refused as {@code POST /refund}, and a path that matches no handler reaches none. A {@code HEAD} runs the
 * {@code GET} handler, so it is refused wherever that {@code GET} is.
 *
 * <p>A request is attested only where {@link PartnerFilter} verified it and said so; one it never saw, such as one
 * under a path it skips, counts as unsafe. Each refusal logs one {@code PAZTPORT_TRACE decision} line.
 */
final class PartnerGate implements HandlerInterceptor {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final List<String> disabled;
    private final String receiver;

    /**
     * @param sessions the partner's sessions, whose list of operations switched off in unsafe sessions applies
     * @param receiver this service's name, for the trace line
     */
    PartnerGate(PartnerSessions sessions, String receiver) {
        this.disabled = sessions.unsafeDisabled();
        this.receiver = receiver;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (SessionStatus.ATTESTED.equals(request.getAttribute(PartnerFilter.SESSION_STATUS))) {
            return true;
        }
        // Every Spring MVC mapping sets the pattern; without one, the raw path is the closest there is.
        String pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) instanceof String p
                ? p : request.getRequestURI();
        String method = request.getMethod();
        if (!disabled.contains(method + " " + pattern)
                && !("HEAD".equals(method) && disabled.contains("GET " + pattern))) {
            return true;
        }
        if (TRACE.isInfoEnabled()) {
            TRACE.info(TraceLines.decisionLine(receiver, "unsafe-session", ReasonCode.UNSAFE_SESSION,
                    PaztportContext.influence()));
        }
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write("{\"reason\":\"UNSAFE_SESSION\"}");
        return false;
    }
}
