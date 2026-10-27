// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import org.paztport.core.VerifyRequestV1;

/**
 * Turns an HTTP request into the transport-neutral {@link VerifyRequestV1} the
 * core verifier takes. The request line and body are rebound here, so core
 * only ever compares a binding it was handed and never learns about HTTP.
 */
public final class HttpVerifyRequestsV1 {

    private HttpVerifyRequestsV1() {
    }

    /**
     * @param receiver the name of the service verifying the request, which
     *     closes the route that is proven against the pinned root
     */
    public static VerifyRequestV1 of(
            String chainHeader, String proofHeader, String method, String path, byte[] body, String receiver) {
        return new VerifyRequestV1(chainHeader, proofHeader, RequestBinding.compute(method, path, body), receiver);
    }
}
