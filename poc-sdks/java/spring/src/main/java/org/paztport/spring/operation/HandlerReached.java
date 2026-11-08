// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.paztport.spring.internal.VerifiedOperation;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Paztport's last interceptor: it marks the request's {@link VerifiedOperation} reached, as every interceptor before
 * it, {@link DispatchCheck} and those the application registers included, has let the request on to the handler. An
 * interceptor that stops the request with its own answer, such as an authorization check writing a 401, leaves it
 * unmarked, so the inbound filter does not attest that answer as the confirmed handler's. It never stops a request.
 * An application interceptor ordered after this one, also at the lowest precedence and registered later, is not
 * told apart.
 */
final class HandlerReached implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (request.getAttribute(VerifiedOperation.ATTRIBUTE) instanceof VerifiedOperation verified) {
            verified.reach();
        }
        return true;
    }
}
