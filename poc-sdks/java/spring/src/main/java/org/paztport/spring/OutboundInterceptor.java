// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.TreeSet;
import org.paztport.core.ContentLabel;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.ProofBundle;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Stamps every outbound RestClient request, and checks every response. The receiver is taken from the request URI
 * host (Docker Compose service names equal hostnames), and the inbound chain and the influence so far come from
 * {@link PaztportContext}, so the stamp names where the call goes and commits to what shaped it.
 *
 * <p>The binding covers the raw path and the raw query, exactly as they go on the wire, so the receiver can bind
 * the same bytes its container hands it without decoding anything.
 *
 * <p>What a response says becomes part of this request, so it is recorded as influence before the caller sees it.
 * The body is read whole, because the attestation covers all of it, and handed back from memory. A response whose
 * attestation verifies contributes its labels; any other — unattested, failing, a refusal, or one received where
 * no verifier is configured — contributes one {@code local-untrusted} entry, so content nobody vouched for still
 * counts against later calls. Every response checked logs one {@code PAZTPORT_TRACE response} line.
 *
 * <p>All of this happens only inside a {@link PaztportContext.Scope}, which the inbound filter opens per request.
 * Outside one (a scheduled job, a startup runner, a control-plane handler) a call is still stamped, with no
 * inbound chain and no influence, and its response is still checked and traced, but nothing is recorded: there
 * is no unit of work to carry it, and a pooled thread would otherwise hand it to whatever ran next.
 */
public final class OutboundInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final StamperV3 stamper;
    private final ProofBundle bundle;
    private final VerifierV3 verifier;
    private final String caller;

    /** {@code verifier} is null where responses cannot be checked; {@code caller} is this service's name. */
    public OutboundInterceptor(StamperV3 stamper, ProofBundle bundle, VerifierV3 verifier, String caller) {
        this.stamper = stamper;
        this.bundle = bundle;
        this.verifier = verifier;
        this.caller = caller;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        URI uri = request.getURI();
        String query = uri.getRawQuery();
        String target = query == null || query.isEmpty() ? uri.getRawPath() : uri.getRawPath() + "?" + query;
        // Outside a scope the context belongs to no unit of work, so it is neither read nor written.
        boolean scoped = PaztportContext.isOpen();
        List<InfluenceEntry> influence = scoped ? PaztportContext.influence() : List.of();

        StamperV3.Stamped stamped = stamper.next(scoped ? PaztportContext.inboundChain() : null, uri.getHost(),
                RequestBinding.compute(request.getMethod().name(), target, body), influence, bundle);

        request.getHeaders().set(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            request.getHeaders().set(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
        }
        String influenceHeader = HttpV3.encodeInfluence(influence);
        if (influenceHeader != null) {
            request.getHeaders().set(PaztportHeaders.INFLUENCE, influenceHeader);
        }

        ClientHttpResponse response = execution.execute(request, body);
        Buffered buffered;
        try {
            // The status first: HttpURLConnection (Spring's simple request factory) hands over an error response's
            // body only once its status has been read, and otherwise throws on every 4xx and 5xx. The JDK client
            // the starter uses has no such order, but an application may give the builder either.
            response.getStatusCode();
            InputStream in = response.getBody();
            buffered = new Buffered(response, in == null ? new byte[0] : in.readAllBytes());
        } catch (IOException e) {
            response.close();
            throw e;
        }
        try {
            record(stamped, uri.getHost(), buffered, scoped);
        } catch (IOException | RuntimeException e) {
            buffered.close();
            throw e;
        }
        return buffered;
    }

    /**
     * Checks the response against the chain that was sent, logs the result, and, inside a scope, adds what the
     * response contributes to the context.
     */
    private void record(StamperV3.Stamped sent, String from, Buffered response, boolean scoped) throws IOException {
        int status = response.getStatusCode().value();
        String src = "http:" + from;
        HttpV3.ResponseCheck check = null;
        String hash;
        if (verifier != null) {
            check = HttpV3.verifyResponse(verifier, sent.chain(), sent.proof(),
                    response.getHeaders().getFirst(PaztportHeaders.RESPONSE), status, response.body, caller);
            hash = check.resultHash();
        } else {
            hash = HttpV3.resultHash(status, response.body);
        }
        // Unscoped, there is nothing to carry it to: recording would leak it into whatever this thread runs next.
        if (scoped) {
            if (check != null && check.result().ok()) {
                PaztportContext.addInfluence(check.labels().stream().map(l -> l.toEntry(src, hash))
                        .toArray(InfluenceEntry[]::new));
            } else {
                PaztportContext.addInfluence(
                        new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, src, hash, null, null));
            }
        }
        if (TRACE.isInfoEnabled()) {
            TRACE.info(traceLine(sent.chain().get(0).rid(), from, check, caller));
        }
    }

    /**
     * {@code PAZTPORT_TRACE response rid=… from=… reason=… receiver=… ✓|✗ labels=…|labels=-}. With no verifier
     * nothing was checked, so the reason is {@code -}. The labels are the verified ones' classes; every value goes
     * through {@link LogSafe}, since the target and the labels come from outside.
     */
    static String traceLine(String rid, String from, HttpV3.ResponseCheck check, String receiver) {
        TreeSet<String> classes = new TreeSet<>();
        if (check != null) {
            check.labels().stream().map(ContentLabel::cls).forEach(c -> classes.add(c.wire()));
        }
        boolean ok = check != null && check.result().ok();
        return String.format("PAZTPORT_TRACE response rid=%s from=%s reason=%s receiver=%s %s labels=%s",
                LogSafe.of(rid), LogSafe.of(from), check == null ? "-" : check.result().reason(),
                LogSafe.of(receiver), ok ? "✓" : "✗",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }

    /** The response, with its body already read into memory, so the caller reads exactly what was checked. */
    private static final class Buffered implements ClientHttpResponse {
        private final ClientHttpResponse delegate;
        private final byte[] body;

        Buffered(ClientHttpResponse delegate, byte[] body) {
            this.delegate = delegate;
            this.body = body;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return delegate.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return delegate.getStatusText();
        }

        @Override
        public HttpHeaders getHeaders() {
            return delegate.getHeaders();
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
