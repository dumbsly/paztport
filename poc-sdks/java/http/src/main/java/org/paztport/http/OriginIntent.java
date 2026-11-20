// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.Collection;
import java.util.List;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.intent.RequestIntent;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.internal.LogSafe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The origin's facts for a handler that compares its request with them (spec intent.md, The receiver's part), read
 * from what the request in the context was handed ({@link RequestContext#handedOn}). It holds no state of its own, so
 * one instance serves every request.
 *
 * <p>A fact is believed only from a hand-over that is verified, one the verifier made because the live order gave
 * {@code OK} at this hop. A request served without that, in audit mode after a failure, at a hop that is off, or at a
 * service that verifies no requests under a mode, has no facts here, and a handler that requires one refuses it
 * {@code INTENT_MISSING} (spec intent.md, A request that did not verify). The names a handler requires come from the
 * service's own configuration, beside the handler, never from the request.
 *
 * <p>The handler compares the request it was sent with the facts and refuses a difference ({@link #deny}). A handler
 * acts on the value it compared: it uses that value, and builds whatever it sends on from compared values, never from
 * the bytes it parsed it from, since another reader of the same bytes may read another value.
 *
 * <p>Each answer that is not {@code OK} logs one {@code PAZTPORT_TRACE intent} line naming the request, this
 * service, the code and the last signer, for the operator, and never a fact's name or value: every fact travels to
 * every later hop, but a log line need not repeat them.
 */
public final class OriginIntent {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final String receiver;

    /** @param receiver this service's name, for the trace line */
    public OriginIntent(String receiver) {
        this.receiver = receiver;
    }

    /**
     * What a handler that requires the facts {@code needs} is answered, as {@link Intent#require} answers over what the
     * request in the context was handed (check P2): {@code OK} when {@code needs} is empty or every name is among
     * the verified facts, {@code INTENT_MISSING} when one is not or nothing verified was handed on (outside a scope
     * included), {@code INTENT_MISMATCH} when the items handed on do not read. Logs one trace line when the answer is
     * not {@code OK}.
     *
     * @param needs the names of the facts the handler requires, from the service's own configuration; not null
     * @throws NullPointerException {@code needs} null
     */
    public ReasonCode require(Collection<String> needs) {
        ReasonCode reason = Intent.require(RequestContext.handedOn(), needs);
        if (reason != ReasonCode.OK) {
            trace(reason);
        }
        return reason;
    }

    /**
     * The origin's facts for the request in the context: those its verified hand-over holds under {@code intent};
     * {@link IntentFacts#NONE} when nothing was handed on (outside a scope included), the hand-over is not verified,
     * the service does not act on {@code intent}, or the items do not read.
     */
    public IntentFacts facts() {
        HandOver handOver = RequestContext.handedOn();
        if (handOver == null || !handOver.verified()) {
            return IntentFacts.NONE;
        }
        RequestIntent read = Intent.readRequest(handOver.under(Intent.NAME));
        return read.reads() ? read.facts() : IntentFacts.NONE;
    }

    /**
     * The refusal of a handler that compared its request with the facts and found a difference: logs one trace line
     * and returns {@link ReasonCode#INTENT_DENIED}, which the handler answers {@code 403 {"reason":"INTENT_DENIED"}}
     * (spec intent.md, Reason codes). The line names neither the fact nor the value compared.
     */
    public ReasonCode deny() {
        trace(ReasonCode.INTENT_DENIED);
        return ReasonCode.INTENT_DENIED;
    }

    /**
     * {@code PAZTPORT_TRACE intent rid=… receiver=… reason=… last=…}: the rid is the verified chain's, else the
     * inbound chain's, else {@code -}; {@code last} is the inbound chain's last signer, else {@code -}. Both come from
     * the request, so they go through {@link LogSafe}, as does the receiver.
     */
    private void trace(ReasonCode reason) {
        if (!TRACE.isInfoEnabled()) {
            return;
        }
        List<Stamp> inbound = RequestContext.inboundChain();
        List<Stamp> chain = RequestContext.verifiedChain() != null ? RequestContext.verifiedChain() : inbound;
        String rid = chain == null || chain.isEmpty() || chain.get(0).rid().isEmpty()
                ? "-" : LogSafe.of(chain.get(0).rid());
        String last = inbound == null || inbound.isEmpty() ? "-" : LogSafe.of(inbound.get(inbound.size() - 1).svc());
        TRACE.info(String.format("PAZTPORT_TRACE intent rid=%s receiver=%s reason=%s last=%s", rid,
                LogSafe.of(receiver), reason, last));
    }
}
