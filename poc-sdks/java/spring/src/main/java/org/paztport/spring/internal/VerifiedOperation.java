// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import java.util.Objects;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.HttpAnswer;

/**
 * The operation a request was verified as received by, which the inbound filter sets as {@link #ATTRIBUTE} on the
 * request's own dispatch where the chain named an operation and the receiver verified the request with it, under a
 * mode or for attestation alone. The check made as a handler is about to run reads it: it checks the first handler
 * the request reaches, however a later filter dispatched it there, and marks it checked, so a dispatch that handler
 * starts is not checked again; and it marks it contradicted when that handler is another operation's, so the filter
 * attests nothing for it. A handler reached by an include cannot set the status, so there the check marks the refusal
 * owed and the filter writes it once the chain returns. Both take it from here. A request without the attribute had
 * no operation confirmed. It is not for an application to use.
 */
public final class VerifiedOperation {

    /** The request attribute that holds it. */
    public static final String ATTRIBUTE = "org.paztport.spring.operation.verified";

    /** The refusal, under {@code enforce}, of a request whose handler is not the operation it was verified for. */
    public static final HttpAnswer REFUSAL = HttpAnswer.refusal(403, ReasonCode.BINDING_MISMATCH);

    private final String operation;
    private final boolean enforced;
    private boolean checked;
    private boolean contradicted;
    private boolean refusalOwed;

    /**
     * @param operation the operation the request was verified as received by
     * @param enforced true where the request was verified under {@code enforce}, so a contradiction is refused
     */
    public VerifiedOperation(String operation, boolean enforced) {
        this.operation = Objects.requireNonNull(operation, "operation");
        this.enforced = enforced;
    }

    /** The operation the request was verified as received by, never null. */
    public String operation() {
        return operation;
    }

    /** Whether the request was verified under {@code enforce}, so a contradiction is refused rather than logged. */
    public boolean enforced() {
        return enforced;
    }

    /** Marks that the first handler the request reached has been checked against this operation. */
    public void check() {
        checked = true;
    }

    /** Whether the first handler the request reached has been checked, so any later one is not. */
    public boolean checked() {
        return checked;
    }

    /** Marks that the handler about to run is not this operation's. */
    public void contradict() {
        contradicted = true;
    }

    /** Whether the handler that ran is not this operation's, so its answer must not be attested. */
    public boolean contradicted() {
        return contradicted;
    }

    /** Marks that the request is refused but the refusal is not written yet, as an included handler cannot write it. */
    public void oweRefusal() {
        refusalOwed = true;
    }

    /** Whether the filter, which holds the response, must write the {@link #REFUSAL} once the chain returns. */
    public boolean refusalOwed() {
        return refusalOwed;
    }
}
