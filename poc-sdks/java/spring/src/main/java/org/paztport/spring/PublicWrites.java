// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import java.util.TreeSet;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.InfluenceRule;
import org.paztport.core.ReasonCode;
import org.paztport.core.StampV3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The public-write rule over the request's influence, so that service code asks one question before it writes
 * somewhere its owner cannot vouch for: may what this request has read go to this destination? The answer is
 * {@link ReasonCode#INFLUENCE_DENIED} when untrusted content sits beside private content that is not the
 * destination owner's, and {@link ReasonCode#OK} otherwise.
 *
 * <p>The destination owner must come from the service's own records, never from request content, or the request
 * could name its own destination owner and pass. Outside a {@link PaztportContext.Scope} there is no influence to
 * judge, so the write is refused rather than assumed clean.
 *
 * <p>Each decision logs one {@code PAZTPORT_TRACE decision} line. It names the receiver, the rule, the result and
 * the influence classes, and never an owner, since owners are people's identifiers.
 */
public final class PublicWrites {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final String receiver;

    /** @param receiver this service's name, for the trace line */
    public PublicWrites(String receiver) {
        this.receiver = receiver;
    }

    /** @param destinationOwner the owner of the destination from trusted records, or null/empty when unknown */
    public ReasonCode decide(String destinationOwner) {
        List<InfluenceEntry> influence = PaztportContext.influence();
        boolean refused = !PaztportContext.isOpen()
                || InfluenceRule.publicWriteRefused(
                        influence.stream().map(InfluenceEntry::fact).toList(), destinationOwner);
        ReasonCode reason = refused ? ReasonCode.INFLUENCE_DENIED : ReasonCode.OK;
        if (TRACE.isInfoEnabled()) {
            TRACE.info(traceLine(reason, influence));
        }
        return reason;
    }

    /** The rid comes from the request, so it goes through {@link LogSafe}, as do the receiver and the classes. */
    private String traceLine(ReasonCode reason, List<InfluenceEntry> influence) {
        List<StampV3> chain = PaztportContext.verifiedChain() != null
                ? PaztportContext.verifiedChain() : PaztportContext.inboundChain();
        String rid = chain == null || chain.isEmpty() || chain.get(0).rid().isEmpty()
                ? "-" : LogSafe.of(chain.get(0).rid());
        TreeSet<String> classes = new TreeSet<>();
        influence.forEach(e -> classes.add(e.cls().wire()));
        return String.format("PAZTPORT_TRACE decision rid=%s receiver=%s rule=public-write reason=%s %s classes=%s",
                rid, LogSafe.of(receiver), reason, reason == ReasonCode.OK ? "✓" : "✗",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }
}
