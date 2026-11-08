// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.HttpAnswer;
import org.paztport.spring.internal.Refusals;
import org.paztport.spring.internal.VerifiedOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Checks, as the first handler the request reaches is about to run, that it is the operation the inbound filter
 * verified the request for. The filter works the operation out from the request as it is when the filter runs; a
 * filter after it that changes the method, the path or the parameters, by wrapping the request or by forwarding it,
 * makes the DispatcherServlet choose another handler. So this works the operation out again, in the same way
 * ({@link OperationResolver#operationOf}), from the handler about to run, the request's method as the handler sees it
 * and the pattern its handler mapping set as {@link HandlerMapping#BEST_MATCHING_PATTERN_ATTRIBUTE}. Without such a
 * filter the two are always the same, since the same mappings answer the same request.
 *
 * <p>Where they differ, one WARN line names both operations, never the path, and the operation is marked contradicted,
 * so the filter attests no answer for it. Under {@code enforce} the request is refused
 * {@code 403 {"reason":"BINDING_MISMATCH"}} and the handler does not run. Under {@code audit}, and on a service that
 * verifies only to decide attestation, it is served unattested, as a request whose chain names another operation is.
 * Only the first handler a request reaches on its own dispatch or on a forward is checked, where the filter recorded
 * the operation ({@link VerifiedOperation}), which is then marked checked. A forward that handler starts, such as a
 * {@code forward:} view, is its own and passes, as does a request the filter did not record, whose chain named no
 * operation and so had none confirmed. Error, async and include dispatches pass too: they carry the attribute over
 * from the request's own dispatch to another handler, such as the error page's.
 */
final class DispatchCheck implements HandlerInterceptor {

    private static final Logger LOG = LoggerFactory.getLogger(DispatchCheck.class);

    private static final HttpAnswer REFUSAL = HttpAnswer.refusal(403, ReasonCode.BINDING_MISMATCH);

    private final OperationResolver operations;
    private final String service;

    /**
     * @param operations what tells the operation of the handler about to run
     * @param service this service's name, for the log line
     */
    DispatchCheck(OperationResolver operations, String service) {
        this.operations = Objects.requireNonNull(operations, "operations");
        this.service = Objects.requireNonNull(service, "service");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        DispatcherType dispatch = request.getDispatcherType();
        if ((dispatch != DispatcherType.REQUEST && dispatch != DispatcherType.FORWARD)
                || !(request.getAttribute(VerifiedOperation.ATTRIBUTE) instanceof VerifiedOperation verified)
                || verified.checked()) {
            return true;
        }
        verified.check();
        String pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) instanceof String p
                ? p : null;
        String dispatched = operations.operationOf(handler, request.getMethod(), pattern);
        if (Objects.equals(dispatched, verified.operation())) {
            return true;
        }
        verified.contradict();
        // Both names come from this service's own table, whose rules allow nothing that could break the line.
        LOG.warn("the request was verified for the operation {} but the handler about to run is the operation {}: a "
                + "filter after Paztport's changed its method, path or parameters, or forwarded it; {}",
                name(verified.operation()), name(dispatched), verified.enforced() ? "refused" : "served unattested");
        if (!verified.enforced()) {
            return true;
        }
        Refusals.write(response, REFUSAL);
        return false;
    }

    /** {@code <service>#<operation>}, or {@code none}. */
    private String name(String operation) {
        return operation == null ? "none" : service + "#" + operation;
    }
}
