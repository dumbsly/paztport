// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import org.paztport.spring.internal.Refusals;
import org.paztport.spring.internal.VerifiedOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Checks, as the first handler the request reaches is about to run, that it is the operation the inbound filter
 * verified the request for. The filter works the operation out from the request as it is when the filter runs; a
 * filter after it that changes the method, the path or the parameters by wrapping the request, or that dispatches it
 * elsewhere by a forward, an include or an async dispatch, makes the DispatcherServlet choose another handler. So this
 * works the operation out again, in the same way ({@link OperationResolver#operationOf}), from the handler about to
 * run, the request's method as the handler sees it and the pattern its handler mapping set as
 * {@link HandlerMapping#BEST_MATCHING_PATTERN_ATTRIBUTE}. Without such a filter the two are always the same, since the
 * same mappings answer the same request.
 *
 * <p>Where they differ, one WARN line names both operations, never the path, and the operation is marked contradicted,
 * so the filter attests no answer for it. Under {@code enforce} the request is refused
 * {@code 403 {"reason":"BINDING_MISMATCH"}} and the handler does not run, nor does any handler a filter dispatches the
 * request to afterwards. A handler reached by an include cannot set the status, so there the refusal is marked owed
 * and the inbound filter, which holds the response, writes it once the chain returns. Under {@code audit}, and on a
 * service that verifies only to decide attestation, the request is served unattested, as a request whose chain names
 * another operation is.
 *
 * <p>Only the first handler a request reaches, by whatever dispatch but the error dispatch, is checked, where the
 * filter recorded the operation ({@link VerifiedOperation}), which is then marked checked. A forward or include that
 * handler starts, such as a {@code forward:} view, is its own and passes, as does the async dispatch that resumes the
 * work it started, and a request the filter did not record, whose chain named no operation and so had none
 * confirmed. The error dispatch passes too: the error page is the container's answer, not an operation, and an error
 * sent before any handler ran makes it the first handler the request reaches.
 */
final class DispatchCheck implements HandlerInterceptor {

    private static final Logger LOG = LoggerFactory.getLogger(DispatchCheck.class);

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
        if (dispatch == DispatcherType.ERROR
                || !(request.getAttribute(VerifiedOperation.ATTRIBUTE) instanceof VerifiedOperation verified)) {
            return true;
        }
        if (verified.checked()) {
            // A request refused once runs no handler afterwards, whatever a filter dispatches it to next.
            return !(verified.enforced() && verified.contradicted());
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
                + "filter after Paztport's changed its method, path or parameters, or dispatched it elsewhere; {}",
                name(verified.operation()), name(dispatched), verified.enforced() ? "refused" : "served unattested");
        if (!verified.enforced()) {
            return true;
        }
        if (dispatch == DispatcherType.INCLUDE) {
            // The container ignores the status an included handler sets, so the inbound filter writes the refusal.
            verified.oweRefusal();
            return false;
        }
        Refusals.write(response, VerifiedOperation.REFUSAL);
        return false;
    }

    /** {@code <service>#<operation>}, or {@code none}. */
    private String name(String operation) {
        return operation == null ? "none" : service + "#" + operation;
    }
}
