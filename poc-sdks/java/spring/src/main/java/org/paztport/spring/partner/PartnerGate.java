// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.HttpAnswer;
import org.paztport.http.PartnerSessions;
import org.paztport.http.RequestContext;
import org.paztport.http.UnsafeOperations;
import org.paztport.http.internal.DecisionLine;
import org.paztport.spring.PartnerFilter;
import org.paztport.spring.internal.SessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Refuses, in any session that is not attested, the operations the partner switched off for unsafe sessions:
 * {@code 403 {"reason":"UNSAFE_SESSION"}}, and the handler does not run.
 *
 * <p>Which operations those are is {@link UnsafeOperations}'s rule, over the pattern of the handler Spring actually
 * dispatched to, which only Spring knows and so this hands over.
 *
 * <p>A request is attested only where {@link PartnerFilter} verified it and said so; one it never saw, such as one
 * under a path it skips, counts as unsafe. Each refusal logs one {@code PAZTPORT_TRACE decision} line.
 */
final class PartnerGate implements HandlerInterceptor {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final UnsafeOperations operations;
    private final String receiver;

    /**
     * @param sessions the partner's sessions, whose list of operations switched off in unsafe sessions applies
     * @param receiver this service's name, for the trace line
     */
    PartnerGate(PartnerSessions sessions, String receiver) {
        this.operations = sessions.unsafeOperations();
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
        if (!operations.refuses(request.getMethod(), pattern)) {
            return true;
        }
        if (TRACE.isInfoEnabled()) {
            TRACE.info(DecisionLine.of(receiver, "unsafe-session", ReasonCode.UNSAFE_SESSION,
                    RequestContext.influence()));
        }
        HttpAnswer refusal = UnsafeOperations.refusal();
        response.setStatus(refusal.status());
        response.setContentType("application/json");
        response.getWriter().write(new String(refusal.json(), StandardCharsets.UTF_8));
        return false;
    }
}
