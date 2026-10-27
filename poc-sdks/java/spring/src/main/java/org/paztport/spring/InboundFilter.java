// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.TreeSet;
import org.paztport.core.Chains;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.ParsedChain;
import org.paztport.core.Peer;
import org.paztport.core.StampV3;
import org.paztport.core.VerifierV3;
import org.paztport.core.VerifyInputV3;
import org.paztport.core.VerifyResult;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Inbound half of the glue. Caches the body, stores the received v3 chain and influence in {@link PaztportContext}
 * for outbound appends, and — on a verifying service — applies the current {@link VerificationMode}:
 *
 * <ul>
 *   <li>{@code OFF} — skip verification, pass through.</li>
 *   <li>{@code AUDIT} — verify, publish an event on failure, always pass through.</li>
 *   <li>{@code ENFORCE} — verify, publish an event and return 403 on failure.</li>
 * </ul>
 *
 * The influence the handler starts from is the verified entries when the request verified, and otherwise the
 * entries as received. Influence that cannot be read is never dropped, because dropping it could hide private data
 * from the rule: wherever it was not verified, it is answered {@code 400 {"reason":"INFLUENCE_MISMATCH"}}.
 *
 * <p>A null verifier skips verification on non-verifying hops. A non-null {@link ReceivedRequestListener} is
 * offered every request first, before any verification, so an application can observe traffic without the SDK
 * knowing why. Every verification logs one {@code PAZTPORT_TRACE request} line.
 */
public final class InboundFilter extends OncePerRequestFilter {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final VerifierV3 verifier;
    private final String receiver;
    private final ModeHolder modeHolder;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;

    public InboundFilter(
            VerifierV3 verifier, String receiver, ModeHolder modeHolder, EventPublisher publisher,
            ReceivedRequestListener listener) {
        this.verifier = verifier;
        this.receiver = receiver;
        this.modeHolder = modeHolder;
        this.publisher = publisher;
        this.listener = listener;
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

        // A pooled thread starts clean even if something escaped an earlier request's finally.
        PaztportContext.clear();
        PaztportContext.setInboundChain(parseChain(chainHeader));
        try {
            if (listener != null) {
                listener.received(chainHeader, proofHeader, influenceHeader, request.getMethod(), target, body);
            }
            VerificationMode mode = verifier == null ? VerificationMode.OFF : modeHolder.get();
            List<InfluenceEntry> influence;
            if (mode != VerificationMode.OFF) {
                // Peer stays null until the transport authenticates one.
                Peer peer = null;
                VerifyInputV3 input = HttpV3.request(chainHeader, proofHeader, influenceHeader, request.getMethod(),
                        target, body, receiver, peer);
                VerifyResult result = verifier.verify(input);
                // On OK these are the entries the last stamp committed to; otherwise what was received.
                influence = parseInfluence(input.influence());
                if (TRACE.isInfoEnabled()) {
                    TRACE.info(traceLine(currentRid(), result, receiver, peer, influence));
                }
                if (!result.ok()) {
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
            chain.doFilter(wrapped, response);
        } finally {
            PaztportContext.clear();
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

    private static void reject(HttpServletResponse response, VerifyResult result) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write(String.format(
                "{\"reason\":\"%s\",\"suspectSvc\":\"%s\",\"suspectInst\":\"%s\"}",
                result.reason(), result.suspectSvc(), result.suspectInst()));
    }

    private static void unreadableInfluence(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.getWriter().write("{\"reason\":\"INFLUENCE_MISMATCH\"}");
    }
}
