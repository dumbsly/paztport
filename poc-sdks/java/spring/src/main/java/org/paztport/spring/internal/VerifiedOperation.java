// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

/**
 * The operation a request was verified as received by, which the inbound filter sets as {@link #ATTRIBUTE} on a
 * request it verified under {@code audit} or {@code enforce} on a service that names its operations, and only on the
 * request's own dispatch. The check made as the handler is about to run reads it, so both take it from here. A request
 * without the attribute is one the filter did not verify in that way; one with a null operation was verified as
 * dispatched to none. It is not for an application to use.
 *
 * @param operation the operation the filter worked out from the handler mappings, or null for none
 * @param enforced true where the request was verified under {@code enforce}, false under {@code audit}
 */
public record VerifiedOperation(String operation, boolean enforced) {

    /** The request attribute that holds it. */
    public static final String ATTRIBUTE = "org.paztport.spring.operation.verified";
}
