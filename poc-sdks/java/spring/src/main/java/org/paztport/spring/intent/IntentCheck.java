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
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Checks, as a handler method annotated {@link RequiresIntent} is about to run, that the request's verified origin
 * stated each fact it requires (spec intent.md, The receiver's part, P2), by {@link OriginIntent#require}. On any
 * answer but {@code OK} it refuses the request, {@code 400 INTENT_MISMATCH} or {@code 403 INTENT_MISSING}, and the
 * handler does not run. A request served without verifying, in audit mode after a failure, with Paztport off, or at a
 * service that verifies only to attest and whose chain failed there, has no facts, so it is refused
 * {@code INTENT_MISSING} in every mode. The refusal is the service's own answer, so it is
 * written in place of the handler's ({@link Refusals#writeInPlaceOfHandler}) and never attested; for a handler
 * reached by an include, which cannot set the status, the inbound filter writes it once the chain returns, as it
 * does the dispatch check's. A handler without the annotation is not touched.
 *
 * <p>The async dispatch that resumes a handler's work, where Spring hands it the result its async work produced and
 * does not run the method again, is not checked again when that same handler method passed this check on the
 * request's own dispatch; the request's scope, and its facts, have ended by then. Any other dispatch to an annotated
 * handler is checked, another handler reached by an async dispatch included, and one that reaches it outside the
 * request's scope is refused, as nothing verified was handed on there.
 *
 * <p>Where the inbound filter does not run, on a path in {@code paztport.unverified-paths} or at a partner's entry,
 * whose {@code PartnerFilter} runs in its place, nothing writes the refusal an included handler owes: the handler
 * still does not run, and nothing is attested. A partner is handed no facts (spec intent.md, Anything across the
 * boundary), so there an annotated handler refuses every call {@code INTENT_MISSING}.
 */
final class IntentCheck implements HandlerInterceptor {

    /** The request attribute that holds the handler method that passed this check on the request's own dispatch. */
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
        if (requires == null || resumes(request, method)) {
            return true;
        }
        ReasonCode reason = intent.require(List.of(requires.value()));
        if (reason == ReasonCode.OK) {
            request.setAttribute(PASSED, method.getMethod());
            return true;
        }
        Refusals.writeInPlaceOfHandler(request, response,
                HttpAnswer.refusal(reason == ReasonCode.INTENT_MISMATCH ? 400 : 403, reason));
        return false;
    }

    /**
     * Whether this is the async dispatch that hands {@code method} the result of the work it started, after that same
     * method passed this check: Spring then does not run the method again, it only returns the result.
     */
    private static boolean resumes(HttpServletRequest request, HandlerMethod method) {
        return request.getDispatcherType() == DispatcherType.ASYNC
                && method.getMethod().equals(request.getAttribute(PASSED))
                && WebAsyncUtils.getAsyncManager(request).hasConcurrentResult();
    }
}
