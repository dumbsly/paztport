// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

/**
 * The operation a request was verified as received by, which the inbound filter sets as {@link #ATTRIBUTE} on the
 * request's own dispatch where the chain named an operation and the receiver verified the request with it, under a
 * mode or for attestation alone. The check made as the handler is about to run reads it, and marks it contradicted
 * when that handler is another operation's, so the filter attests nothing for it; so both take it from here. A request
 * without the attribute had no operation confirmed. It is not for an application to use.
 */
public final class VerifiedOperation {

    /** The request attribute that holds it. */
    public static final String ATTRIBUTE = "org.paztport.spring.operation.verified";

    private final String operation;
    private final boolean enforced;
    private boolean contradicted;

    /**
     * @param operation the operation the request was verified as received by
     * @param enforced true where the request was verified under {@code enforce}, so a contradiction is refused
     */
    public VerifiedOperation(String operation, boolean enforced) {
        this.operation = operation;
        this.enforced = enforced;
    }

    public String operation() {
        return operation;
    }

    public boolean enforced() {
        return enforced;
    }

    /** Marks that the handler about to run is not this operation's. */
    public void contradict() {
        contradicted = true;
    }

    /** Whether the handler that ran is not this operation's, so its answer must not be attested. */
    public boolean contradicted() {
        return contradicted;
    }
}
