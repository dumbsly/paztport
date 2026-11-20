// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.intent;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Objects;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.HttpAnswer;
import org.paztport.http.OriginIntent;
import org.paztport.spring.internal.Refusals;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Checks, as a handler method annotated {@link RequiresIntent} is about to run, that the request's verified origin
 * stated each fact it requires (spec intent.md, The receiver's part, P2), by {@link OriginIntent#require}. On any
 * answer but {@code OK} it refuses the request, {@code 400 INTENT_MISMATCH} or {@code 403 INTENT_MISSING}, and the
 * handler does not run. A request served without verifying, in audit mode after a failure or with Paztport off, has
 * no facts, so it is refused {@code INTENT_MISSING} in every mode. The refusal is the service's own answer, so it is
 * written in place of the handler's ({@link Refusals#writeInPlaceOfHandler}) and never attested; for a handler
 * reached by an include, which cannot set the status, the inbound filter writes it once the chain returns, as it
 * does the dispatch check's. A handler without the annotation is not touched.
 *
 * <p>The async dispatch that resumes a handler's work is not checked again where that handler passed this check on
 * the request's dispatch; the request's scope, and its facts, have ended by then. Any other dispatch to an annotated
 * handler is checked, and one that reaches it outside the request's scope is refused, as nothing verified was handed
 * on there.
 */
final class IntentCheck implements HandlerInterceptor {

    /** The request attribute that marks a request whose handler passed this check. */
    private static final String PASSED = IntentCheck.class.getName() + ".passed";

    private final OriginIntent intent;

    /** @param intent what reads the request's facts and answers what a handler requires */
    IntentCheck(OriginIntent intent) {
        this.intent = Objects.requireNonNull(intent, "intent");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        RequiresIntent requires = method.getMethodAnnotation(RequiresIntent.class);
        if (requires == null
                || (request.getDispatcherType() == DispatcherType.ASYNC && request.getAttribute(PASSED) != null)) {
            return true;
        }
        ReasonCode reason = intent.require(List.of(requires.value()));
        if (reason == ReasonCode.OK) {
            request.setAttribute(PASSED, Boolean.TRUE);
            return true;
        }
        Refusals.writeInPlaceOfHandler(request, response,
                HttpAnswer.refusal(reason == ReasonCode.INTENT_MISMATCH ? 400 : 403, reason));
        return false;
    }
}
