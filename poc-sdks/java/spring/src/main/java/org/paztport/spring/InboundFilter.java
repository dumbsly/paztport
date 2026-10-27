// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.TreeSet;
import org.paztport.core.Chains;
import org.paztport.core.ContentLabel;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.ParsedChain;
import org.paztport.core.Peer;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierV3;
import org.paztport.core.VerifyInputV3;
import org.paztport.core.VerifyResult;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Inbound half of the glue. Caches the body, stores the received v3 chain and influence in {@link PaztportContext}
 * for outbound appends, and — on a verifying service — applies the current {@link VerificationMode}:
 *
 * <ul>
 *   <li>{@code OFF} — skip verification, pass through.</li>
 *   <li>{@code AUDIT} — verify, publish an event on failure, and pass through, unless the influence cannot be
 *       read: that is answered 400 in every mode, as below.</li>
 *   <li>{@code ENFORCE} — verify, publish an event and return 403 on failure.</li>
 * </ul>
 *
 * The influence the handler starts from is the verified entries when the request verified, and otherwise the
 * entries as received. Influence that cannot be read is never dropped, because dropping it could hide private data
 * from the rule: in every mode, it is answered {@code 400 {"reason":"INFLUENCE_MISMATCH"}}.
 *
 * <p>A service holding a stamp key attests what it answers: one stamp on the chain it received, back to the caller,
 * binding the status, the body and the labels the handler gave it ({@link PaztportContext#label}), sent as
 * {@code X-Path-Response}. It attests only a request whose chain verified here or was not checked here (a
 * non-verifying service, or mode {@code OFF}); a request it refused or that failed in {@code AUDIT} gets no
 * attestation, because the stamp would vouch for a chain this service knows to be bad. The body is held until the
 * handler returns, since the stamp covers all of it. A handler that throws sends no attestation, and a body the
 * container writes afterwards (an error page after {@code sendError}) is not the one attested; either way the
 * caller cannot verify it and counts it as untrusted. An async response is not attested either, because its body
 * is written after the filter has returned: it is sent whole when the async work completes, without
 * {@code X-Path-Response}, and its caller counts it as untrusted.
 *
 * <p>Under mutual TLS the request is verified against the sender the handshake authenticated ({@link PeerIdentity}):
 * the chain's last signer must be the service its certificate names, and every result, so every refusal and every
 * event, names that service at the address it connected from. Without a client certificate there is no peer.
 *
 * <p>Each request is served inside a {@link PaztportContext.Scope}, so what its handler and its calls learn is
 * carried for the request and dropped when it ends. Async work after the handler returns runs outside it. A scope
 * that other code left open on the thread is ended, with a warning, before the request's own is opened.
 *
 * <p>A null verifier skips verification on non-verifying hops. A non-null {@link ReceivedRequestListener} is
 * offered every request first, before any verification, so an application can observe traffic without the SDK
 * knowing why. Every verification logs one {@code PAZTPORT_TRACE request} line.
 */
public final class InboundFilter extends OncePerRequestFilter {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");
    private static final Logger LOG = LoggerFactory.getLogger(InboundFilter.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final VerifierV3 verifier;
    private final String receiver;
    private final ModeHolder modeHolder;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;
    private final StamperV3 stamper;

    /** {@code verifier} is null on a hop that does not verify, {@code stamper} on one that does not attest. */
    public InboundFilter(
            VerifierV3 verifier, String receiver, ModeHolder modeHolder, EventPublisher publisher,
            ReceivedRequestListener listener, StamperV3 stamper) {
        this.verifier = verifier;
        this.receiver = receiver;
        this.modeHolder = modeHolder;
        this.publisher = publisher;
        this.listener = listener;
        this.stamper = stamper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Control-plane endpoints are not part of the attested data path.
        String path = request.getRequestURI();
        return path.startsWith("/admin") || path.startsWith("/debug") || path.startsWith("/actuator");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = CachedBodyHttpServletRequest.readAll(request);
        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(request, body);

        String chainHeader = request.getHeader(PaztportHeaders.CHAIN);
        String proofHeader = request.getHeader(PaztportHeaders.PROOF);
        String influenceHeader = request.getHeader(PaztportHeaders.INFLUENCE);
        String target = target(request);

        // The scope starts clean and is emptied when the request ends, so nothing passes between requests.
        List<StampV3> inbound = parseChain(chainHeader);
        if (PaztportContext.isOpen()) {
            // Other code on this pooled thread opened a scope and never closed it. Refusing to open ours would fail
            // this request and every later one served here, so the stale scope is ended and the request served.
            LOG.warn("a paztport context scope was leaked on thread {}; ending it before serving this request",
                    LogSafe.of(Thread.currentThread().getName()));
            PaztportContext.reset();
        }
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.setInboundChain(inbound);
            if (listener != null) {
                listener.received(chainHeader, proofHeader, influenceHeader, request.getMethod(), target, body);
            }
            VerificationMode mode = verifier == null ? VerificationMode.OFF : modeHolder.get();
            List<InfluenceEntry> influence;
            // True when the chain verified here or was not checked here: the chains this service may attest onto.
            boolean vouchable = true;
            if (mode != VerificationMode.OFF) {
                // Under mutual TLS, the sender the handshake authenticated; null without a client certificate.
                Peer peer = PeerIdentity.from(request);
                VerifyInputV3 input = HttpV3.request(chainHeader, proofHeader, influenceHeader, request.getMethod(),
                        target, body, receiver, peer);
                VerifyResult result = verifier.verify(input);
                // On OK these are the entries the last stamp committed to; otherwise what was received.
                influence = parseInfluence(input.influence());
                if (TRACE.isInfoEnabled()) {
                    TRACE.info(traceLine(currentRid(), result, receiver, peer, influence));
                }
                if (!result.ok()) {
                    vouchable = false;
                    publisher.publish(new AttestationEvent(
                            result.reason().name(), result.suspectSvc(), result.suspectInst(),
                            currentRid(), mode == VerificationMode.AUDIT));
                    if (mode == VerificationMode.ENFORCE) {
                        reject(response, result);
                        return;
                    }
                }
            } else {
                influence = parseInfluence(HttpV3.decodeInfluence(influenceHeader));
            }
            if (influence == null) {
                unreadableInfluence(response);
                return;
            }
            PaztportContext.addInfluence(influence.toArray(InfluenceEntry[]::new));
            if (stamper == null || inbound == null || !vouchable) {
                chain.doFilter(wrapped, response);
                return;
            }
            ContentCachingResponseWrapper cached = new ContentCachingResponseWrapper(response);
            chain.doFilter(wrapped, cached);
            if (request.isAsyncStarted()) {
                // The handler returned before writing its body, so there is nothing yet to attest. The body is
                // written into the wrapper later, on another thread, and must still reach the caller whole.
                request.getAsyncContext().addListener(new CopyWhenComplete(cached));
                return;
            }
            attest(cached, inbound);
            cached.copyBodyToResponse();
        }
    }

    /** Sends an async response's body, held by the wrapper, once the async work has finished writing it. */
    private record CopyWhenComplete(ContentCachingResponseWrapper cached) implements AsyncListener {
        @Override
        public void onComplete(AsyncEvent event) throws IOException {
            cached.copyBodyToResponse();
        }

        @Override
        public void onTimeout(AsyncEvent event) {
        }

        @Override
        public void onError(AsyncEvent event) {
        }

        @Override
        public void onStartAsync(AsyncEvent event) {
        }
    }

    /**
     * Sets {@code X-Path-Response} over the status and the body the handler left in {@code cached}. The chain the
     * handler was given is used, not whatever the context holds now, so a handler cannot steer what is vouched
     * for. A rid or label the binding cannot carry leaves the response unattested rather than failing it.
     */
    private void attest(ContentCachingResponseWrapper cached, List<StampV3> inbound) {
        if (cached.isCommitted()) {
            return;
        }
        List<ContentLabel> labels = PaztportContext.labels();
        try {
            String hash = HttpV3.resultHash(cached.getStatus(), cached.getContentAsByteArray());
            StampV3 stamp = stamper.respond(inbound, hash, inbound.get(0).rid(), labels);
            cached.setHeader(PaztportHeaders.RESPONSE, HttpV3.encodeResponse(stamp, labels));
        } catch (IllegalArgumentException e) {
            // Served unattested, so the caller records it as local-untrusted; the operator learns why here.
            LOG.warn("response left unattested: rid={} {}", LogSafe.of(inbound.get(0).rid()),
                    LogSafe.of(e.getMessage()));
        }
    }

    /** The raw path, plus {@code ?} and the raw query when there is one: what the caller's binding covers. */
    private static String target(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null || query.isEmpty() ? request.getRequestURI() : request.getRequestURI() + "?" + query;
    }

    /** The received chain as v3 stamps, or null when there is none or it does not parse. */
    private static List<StampV3> parseChain(String chainHeader) {
        ParsedChain parsed = Chains.parse(HttpV3.decodeChain(chainHeader), false);
        return parsed.ok() ? parsed.stamps().stream().map(StampV3.class::cast).toList() : null;
    }

    /** The entries, or null when the header could not be read as influence. */
    private static List<InfluenceEntry> parseInfluence(JsonNode node) {
        try {
            return Influence.parse(node);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String currentRid() {
        List<StampV3> chain = PaztportContext.inboundChain();
        return chain != null ? chain.get(0).rid() : "";
    }

    /**
     * {@code PAZTPORT_TRACE request rid=… reason=… receiver=… ✓|✗ peer=…|peer=none classes=…|classes=-}. The rid
     * and the classes come from the request, so every value goes through {@link LogSafe}.
     */
    static String traceLine(String rid, VerifyResult result, String receiver, Peer peer,
            List<InfluenceEntry> influence) {
        TreeSet<String> classes = new TreeSet<>();
        if (influence != null) {
            influence.forEach(e -> classes.add(e.cls().wire()));
        }
        return String.format("PAZTPORT_TRACE request rid=%s reason=%s receiver=%s %s %s classes=%s",
                rid.isEmpty() ? "-" : LogSafe.of(rid), result.reason(), LogSafe.of(receiver),
                result.ok() ? "✓" : "✗",
                peer == null ? "peer=none" : "peer=" + LogSafe.of(peer.svc()) + " (mTLS)",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }

    /** The suspect is whatever its signer chose, so the body is written by an encoder, never by formatting. */
    private static void reject(HttpServletResponse response, VerifyResult result) throws IOException {
        ObjectNode body = JSON.createObjectNode()
                .put("reason", result.reason().name())
                .put("suspectSvc", result.suspectSvc())
                .put("suspectInst", result.suspectInst());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(JSON.writeValueAsString(body));
    }

    private static void unreadableInfluence(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.getWriter().write("{\"reason\":\"INFLUENCE_MISMATCH\"}");
    }
}
