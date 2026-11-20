// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import java.util.Objects;
import org.paztport.core.intent.Intent;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.internal.VerifyInputs;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The partner's receiver, in place of {@link HttpReceiver}, with no web framework and no request scope: another
 * organisation's calls are verified in the session the caller named, against the keyring and root it presented in
 * that session's handshake, rather than against this organisation's own. It has no modes, publishes no events and
 * attests no responses.
 *
 * <p>The session is named by {@code X-Path-Session}, and is looked up for the peer the transport authenticated, by
 * its certificate's issuer and common name ({@link PeerCert}):
 *
 * <ul>
 *   <li>No header, or a blank one, means the caller never opened a session, which is treated as unsafe.</li>
 *   <li>A header that does not name a live session this peer opened is refused {@code 403 SESSION_UNKNOWN}: another
 *       peer's id (another name, or the same name under another issuer), an evicted or expired one, one from
 *       before a restart, or a caller with no certificate. It is never taken as unsafe, or a caller could step down
 *       from a session it was refused in by naming a wrong one.</li>
 *   <li>In an unsafe session nothing is verified, so nothing from the request is believed: the handler is handed
 *       nothing and holds no verified chain, whatever headers came, its blocks included, which are not read, and the
 *       endpoints switched off for such sessions are refused ({@link UnsafeEndpoints}).</li>
 *   <li>In an attested session the chain is verified in the live order by that session's own verifier, which
 *       carries this partner's extension settings, with this service as receiver and the peer as last signer, and a
 *       failure is refused {@code 403} with its code. Only on {@code OK} does the handler get the verified chain, its
 *       one block, and the verified hand-over, owners included. A partner that acts on {@code influence} first
 *       refuses an item that does not read, {@code 400 INFLUENCE_MISMATCH}; one that acts on {@code intent} then
 *       refuses any item under it, {@code 400 INTENT_MISMATCH}, since the origin's facts do not cross the boundary,
 *       so a handler here is handed no facts.</li>
 * </ul>
 *
 * <p>Each call logs one {@code PAZTPORT_TRACE request} line naming its session's status. Like {@link HttpReceiver},
 * it touches no thread-local: carrying its result for the handler is the binding's work
 * ({@link RequestContext#accept(PartnerReceiver, InboundRequest, PeerCert)} for blocking Java).
 */
public final class PartnerReceiver {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final PartnerSessions sessions;
    private final String receiver;

    /**
     * @param sessions the sessions this partner has opened
     * @param receiver this service's name, the partner's entry: every boundary stamp must be addressed to it
     */
    public PartnerReceiver(PartnerSessions sessions, String receiver) {
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.receiver = Objects.requireNonNull(receiver, "receiver");
    }

    /**
     * Decides one call.
     *
     * @param request the call as it arrived
     * @param peer the client certificate the transport authenticated, or null without one
     */
    public PartnerAccepted accept(InboundRequest request, PeerCert peer) {
        String sessionHeader = HttpWire.headerValue(request.header(PaztportHeaders.SESSION));
        String chainHeader = request.header(PaztportHeaders.CHAIN);
        Peer sender = peer == null ? null : peer.peer();
        // Read once: for the trace line, and then for the call, but nothing is taken from it until it has verified.
        String chain = HttpWire.decodeChain(chainHeader);
        ParsedChain parsed = Chains.parse(chain);
        List<Stamp> received = HttpReceiver.stamps(parsed);
        String rid = received != null ? received.get(0).rid() : "";

        PartnerSessions.Session session = null;
        if (sessionHeader != null) {
            session = sessions.find(peer == null ? null : peer.issuer(), sender == null ? null : sender.svc(),
                    sessionHeader);
            if (session == null) {
                VerifyResult unknown = new VerifyResult(ReasonCode.SESSION_UNKNOWN,
                        sender == null ? "" : sender.svc(), sender == null ? "" : sender.inst(), null);
                trace(HttpReceiver.traceLine(rid, unknown, receiver, sender, List.of(), "unknown"));
                return PartnerAccepted.refused(HttpAnswer.refusal(403, ReasonCode.SESSION_UNKNOWN), null);
            }
        }
        if (session == null || !session.attested()) {
            trace(String.format("PAZTPORT_TRACE request rid=%s reason=- receiver=%s %s session=unsafe",
                    rid.isEmpty() ? "-" : LogSafe.of(rid), LogSafe.of(receiver), HttpReceiver.peerField(sender)));
            return PartnerAccepted.unsafe(sessions.extensions());
        }

        String blocksHeader = request.header(PaztportHeaders.EXTENSIONS);
        VerifyInput input = VerifyInputs.request(chain, parsed, request.header(PaztportHeaders.PROOF),
                blocksHeader, request.method(), request.target(), request.body(), receiver, null, sender);
        VerifyResult result = session.verifier().verify(input);
        trace(HttpReceiver.traceLine(rid, result, receiver, sender, HttpReceiver.classes(result), "attested"));
        if (!result.ok()) {
            return PartnerAccepted.refused(HttpAnswer.refusal(403, result.reason()), result);
        }
        HttpAnswer unread = HttpReceiver.unreadInfluence(sessions.extensions(), result.handOver(), rid);
        if (unread == null) {
            unread = intentItem(sessions.extensions(), result.handOver(), rid);
        }
        if (unread != null) {
            return PartnerAccepted.refused(unread, result);
        }
        // Check 9a held, so the blocks read as one per stamp.
        List<Block> blocks = HttpReceiver.carriedBlocks(received, HttpWire.decodeBlocks(blocksHeader));
        return PartnerAccepted.attested(received, blocks, result, sessions.extensions());
    }

    /**
     * The refusal of a partner that acts on {@code intent} and is handed any item under it, in any stamp,
     * {@code 400 INTENT_MISMATCH}; null otherwise (spec intent.md, Anything across the boundary). The origin's facts
     * do not cross the boundary, and an item in the boundary block would be the egress's own statement, which the
     * checks would read as the first stamp's: so no item is read as facts here, whether or not it reads. A block
     * that names {@code intent} with no items is served. It runs after {@link HttpReceiver#unreadInfluence}, as
     * {@link HttpReceiver#unreadIntent} does at a service. The log names the signer of the first block holding an
     * item, never the item.
     *
     * @param handOver what the partner is handed, verified
     */
    private static HttpAnswer intentItem(ExtensionSettings settings, HandOver handOver, String rid) {
        if (handOver == null || !settings.actsOn().contains(Intent.NAME)) {
            return null;
        }
        for (HandOver.StampItems stamp : handOver.under(Intent.NAME)) {
            if (stamp.items() != null && !stamp.items().isEmpty()) {
                HttpReceiver.LOG.warn("call refused, an intent item crossed the boundary: rid={} signer={}",
                        LogSafe.of(rid), LogSafe.of(stamp.svc()));
                return HttpAnswer.refusal(400, ReasonCode.INTENT_MISMATCH);
            }
        }
        return null;
    }

    private static void trace(String line) {
        if (TRACE.isInfoEnabled()) {
            TRACE.info(line);
        }
    }
}
