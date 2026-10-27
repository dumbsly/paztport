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
 * for outbound appends, and — on a service that verifies requests ({@code paztport.verify=true}) — applies the
 * current {@link VerificationMode}, read once per request so that a switch cannot catch a request half-way:
 *
 * <ul>
 *   <li>{@code OFF} — Paztport is off on this hop: nothing is verified, not even to decide attestation, nothing is
 *       published, and the response goes back without {@code X-Path-Response}. The chain and influence are still
 *       carried, so the handler's own calls are stamped as before, and unreadable influence is still answered
 *       400.</li>
 *   <li>{@code AUDIT} — verify, publish an event on failure, and pass through, unless the influence cannot be
 *       read: that is answered 400 in every mode, as below.</li>
 *   <li>{@code ENFORCE} — verify, publish an event and return 403 on failure.</li>
 * </ul>
 *
 * The influence the handler starts from is the verified entries when the request verified, and otherwise the
 * entries as received. Influence that cannot be read is never dropped, because dropping it could hide private data
 * from the rule: in every mode, a non-origin service answers it {@code 400 {"reason":"INFLUENCE_MISMATCH"}}.
 *
 * <p>An origin starts every request tree afresh: it ignores the inbound chain and influence, so its handler starts
 * from none, and it never attests.
 *
 * <p>A non-origin service holding a stamp key and a verifier attests what it answers: one stamp on the chain it
 * received, back to the caller, binding the status, the body and the labels the handler gave it
 * ({@link PaztportContext#label}), sent as {@code X-Path-Response}. It attests only a chain that passed the full
 * live order here — its own verifier, itself as receiver, the request's proof and influence, the peer — whether or
 * not it enforces, unless an operator has switched its verification {@code OFF}. A response stamp is shaped like a
 * request stamp, so attesting a chain nobody checked would let whoever sent it mint stamps under this service's key:
 * a one-stamp chain with an empty signature would come back as a valid origin stamp from this service. Where the
 * request was already verified under the mode, that result decides; otherwise the chain is verified for attestation
 * alone, once, and a failure only withholds the attestation: the request is served, and nothing is published. A
 * request it refused, or that failed in {@code AUDIT}, gets no attestation either. A service without a verifier
 * never attests.
 *
 * <p>{@code OFF} withholds attestation only on a service that verifies requests, because only there is it a choice:
 * the operator set that mode, at startup or through {@code /admin/mode}, to take Paztport off the hop, and a hop
 * that is off must not run Paztport's work at all, or {@code OFF} would not be a baseline to measure against. A
 * service that does not verify requests has no mode to switch; it is not off, it only does not enforce, so its
 * verifier still decides attestation as above. Switching a hop off is fail-safe: its caller records an unattested
 * response as {@code local-untrusted}, so it can only add caution downstream, never vouch for anything.
 *
 * <p>The body is held until the handler returns, since the stamp covers all of it. A handler that throws sends no
 * attestation, and a body the container writes afterwards (an error page after {@code sendError}) is not the one
 * attested; either way the caller cannot verify it and counts it as untrusted. An async response is not attested
 * either, because its body is written after the filter has returned: it is sent whole when the async work
 * completes, without {@code X-Path-Response}, and its caller counts it as untrusted.
 *
 * <p>Under mutual TLS the request is verified against the sender the handshake authenticated ({@link PeerIdentity}):
 * the chain's last signer must be the service its certificate names, and every result, so every refusal and every
 * event, names that service at the address it connected from. Without a client certificate there is no peer.
 *
 * <p>Each request is served inside a {@link PaztportContext.Scope}, so what its handler and its calls learn is
 * carried for the request and dropped when it ends. Async work after the handler returns runs outside it. A scope
 * that other code left open on the thread is ended, with a warning, before the request's own is opened.
 *
 * <p>A non-null {@link ReceivedRequestListener} is offered every request first, before any verification, so an
 * application can observe traffic without the SDK knowing why. Every verification, including one run only to
 * decide attestation, logs one {@code PAZTPORT_TRACE request} line.
 */
public final class InboundFilter extends OncePerRequestFilter {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");
    private static final Logger LOG = LoggerFactory.getLogger(InboundFilter.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final VerifierV3 verifier;
    private final boolean verifyRequests;
    private final boolean origin;
    private final String receiver;
    private final ModeHolder modeHolder;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;
    private final StamperV3 stamper;

    /**
     * @param verifier this service's verifier, or null where it holds no keyring, root and pin; without one it
     *     neither verifies nor attests
     * @param verifyRequests true where requests are verified under the mode ({@code paztport.verify=true}); it
     *     needs a verifier, a mode holder and a publisher, and under {@code OFF} it neither verifies nor attests.
     *     Otherwise the verifier only decides attestation.
     * @param origin true for an entry point ({@code paztport.origin=true}), which ignores the inbound chain and
     *     influence and never attests
     * @param receiver this service's name
     * @param stamper this service's stamper, or null where it has no stamp key and so cannot attest
     */
    public InboundFilter(
            VerifierV3 verifier, boolean verifyRequests, boolean origin, String receiver, ModeHolder modeHolder,
            EventPublisher publisher, ReceivedRequestListener listener, StamperV3 stamper) {
        if (verifyRequests && (verifier == null || modeHolder == null || publisher == null)) {
            throw new IllegalArgumentException("verifying requests needs a verifier, a mode holder and a publisher");
        }
        this.verifier = verifier;
        this.verifyRequests = verifyRequests;
        this.origin = origin;
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

        // The scope starts clean and is emptied when the request ends, so nothing passes between requests. An origin
        // starts a new request tree, so whatever chain came with the request is not carried.
        List<StampV3> received = parseChain(chainHeader);
        List<StampV3> inbound = origin ? null : received;
        String rid = received != null ? received.get(0).rid() : "";
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
            VerificationMode mode = verifyRequests ? modeHolder.get() : VerificationMode.OFF;
            // The operator took Paztport off this hop. A service that does not verify requests is OFF here too, but
            // has no mode to switch, so it still attests what verifies.
            boolean switchedOff = verifyRequests && mode == VerificationMode.OFF;
            // Under mutual TLS, the sender the handshake authenticated; null without a client certificate.
            Peer peer = PeerIdentity.from(request);
            List<InfluenceEntry> influence;
            // The live order's result on this request here, once it has run: it decides attestation.
            VerifyResult checked = null;
            if (mode != VerificationMode.OFF) {
                VerifyInputV3 input = HttpV3.request(chainHeader, proofHeader, influenceHeader, request.getMethod(),
                        target, body, receiver, peer);
                checked = verifier.verify(input);
                // On OK these are the entries the last stamp committed to; otherwise what was received.
                influence = parseInfluence(input.influence());
                trace(rid, checked, peer, influence);
                if (!checked.ok()) {
                    publisher.publish(new AttestationEvent(
                            checked.reason().name(), checked.suspectSvc(), checked.suspectInst(),
                            rid, mode == VerificationMode.AUDIT));
                    if (mode == VerificationMode.ENFORCE) {
                        reject(response, checked);
                        return;
                    }
                } else if (!origin && inbound != null) {
                    PaztportContext.markVerified(inbound);
                }
            } else {
                influence = parseInfluence(HttpV3.decodeInfluence(influenceHeader));
            }
            // An origin starts the tree with no influence: what a client claims is not carried, so it cannot hide
            // anything by being unreadable either.
            if (!origin) {
                if (influence == null) {
                    unreadableInfluence(response);
                    return;
                }
                PaztportContext.addInfluence(influence.toArray(InfluenceEntry[]::new));
            }
            boolean attesting = !switchedOff && stamper != null && verifier != null && !origin && inbound != null;
            if (attesting && checked == null) {
                // A hop that does not verify requests, so verified here for attestation alone: never refused, never
                // published. Run at most once per request, since the live order spends the request's nonce.
                checked = verifier.verify(HttpV3.request(chainHeader, proofHeader, influenceHeader,
                        request.getMethod(), target, body, receiver, peer));
                trace(rid, checked, peer, influence);
                if (checked.ok()) {
                    PaztportContext.markVerified(inbound);
                }
            }
            if (!attesting || !checked.ok()) {
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

    private void trace(String rid, VerifyResult result, Peer peer, List<InfluenceEntry> influence) {
        if (TRACE.isInfoEnabled()) {
            TRACE.info(traceLine(rid, result, receiver, peer, influence));
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
     * Sets {@code X-Path-Response} over the status and the body the handler left in {@code cached}. Called only
     * for a chain that verified here. The chain the handler was given is used, not whatever the context holds now,
     * so a handler cannot steer what is vouched for. A rid or label the binding cannot carry leaves the response
     * unattested rather than failing it.
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
                peer == null ? "peer=none" : "peer=" + peerName(peer.svc()) + " (mTLS)",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }

    /** A certificate that names no service is shown as {@code ""}, so the trace never reads {@code peer= (mTLS)}. */
    private static String peerName(String svc) {
        return svc.isEmpty() ? "\"\"" : LogSafe.of(svc);
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
