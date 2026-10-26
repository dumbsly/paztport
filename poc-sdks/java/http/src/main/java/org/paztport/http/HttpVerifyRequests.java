// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import org.paztport.core.VerifyRequest;

/**
 * Turns an HTTP request into the transport-neutral {@link VerifyRequest} the
 * core verifier takes. The request line and body are rebound here, so core
 * only ever compares a binding it was handed and never learns about HTTP.
 */
public final class HttpVerifyRequests {

    private HttpVerifyRequests() {
    }

    /**
     * @param receiver the name of the service verifying the request, which
     *     closes the route that is proven against the pinned root
     */
    public static VerifyRequest of(
            String chainHeader, String proofHeader, String method, String path, byte[] body, String receiver) {
        return new VerifyRequest(chainHeader, proofHeader, RequestBinding.compute(method, path, body), receiver, null);
    }
}
