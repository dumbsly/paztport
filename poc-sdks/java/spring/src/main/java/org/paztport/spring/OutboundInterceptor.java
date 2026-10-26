// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.IOException;
import java.net.URI;
import org.paztport.core.OutboundStamper;
import org.paztport.core.PathChain;
import org.paztport.core.ProofBundle;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Stamps every outbound RestClient request. The target service is taken from the
 * request URI host (Docker Compose service names equal hostnames), and the
 * inbound chain comes from {@link PaztportContext}.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private final OutboundStamper stamper;
    private final ProofBundle bundle;

    public OutboundInterceptor(OutboundStamper stamper, ProofBundle bundle) {
        this.stamper = stamper;
        this.bundle = bundle;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        URI uri = request.getURI();
        PathChain inbound = PaztportContext.inboundChain();

        OutboundStamper.StampedHeaders headers =
                stamper.stamp(inbound, request.getMethod().name(), uri.getPath(), body, uri.getHost(), bundle);

        request.getHeaders().set(PaztportHeaders.CHAIN, headers.chainHeader());
        if (headers.proofHeader() != null) {
            request.getHeaders().set(PaztportHeaders.PROOF, headers.proofHeader());
        }
        return execution.execute(request, body);
    }
}
