// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.ProofBundle;
import org.paztport.core.StamperV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Stamps every outbound RestClient request. The receiver is taken from the request URI host (Docker Compose
 * service names equal hostnames), and the inbound chain and the influence so far come from
 * {@link PaztportContext}, so the stamp names where the call goes and commits to what shaped it.
 *
 * <p>The binding covers the raw path and the raw query, exactly as they go on the wire, so the receiver can bind
 * the same bytes its container hands it without decoding anything.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private final StamperV3 stamper;
    private final ProofBundle bundle;

    public OutboundInterceptor(StamperV3 stamper, ProofBundle bundle) {
        this.stamper = stamper;
        this.bundle = bundle;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        URI uri = request.getURI();
        String query = uri.getRawQuery();
        String target = query == null || query.isEmpty() ? uri.getRawPath() : uri.getRawPath() + "?" + query;
        List<InfluenceEntry> influence = PaztportContext.influence();

        StamperV3.Stamped stamped = stamper.next(PaztportContext.inboundChain(), uri.getHost(),
                RequestBinding.compute(request.getMethod().name(), target, body), influence, bundle);

        request.getHeaders().set(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            request.getHeaders().set(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
        }
        String influenceHeader = HttpV3.encodeInfluence(influence);
        if (influenceHeader != null) {
            request.getHeaders().set(PaztportHeaders.INFLUENCE, influenceHeader);
        }
        return execution.execute(request, body);
    }
}
