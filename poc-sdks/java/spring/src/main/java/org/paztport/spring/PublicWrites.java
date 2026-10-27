// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import java.util.TreeSet;
import org.paztport.core.InfluenceClass;
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
 * <p>It answers a second question too, {@link #shapedOnlyByTrusted}, for writes into the service's own trusted
 * records, which the rule cannot judge.
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

    /**
     * The public-write rule over the influence in the context. That influence is verified only where the request's
     * chain verified at this hop. In {@code off} mode, after a chain failed in audit mode, or in an unsafe partner
     * session, it may be incomplete or empty, and the rule cannot refuse for content it is not shown: a partner
     * must therefore list its public writes in {@code paztport.partner.unsafe-disabled}, so that an unsafe session
     * never reaches them.
     *
     * @param destinationOwner the owner of the destination from trusted records, or null/empty when unknown
     */
    public ReasonCode decide(String destinationOwner) {
        List<InfluenceEntry> influence = PaztportContext.influence();
        boolean refused = !PaztportContext.isOpen()
                || InfluenceRule.publicWriteRefused(
                        influence.stream().map(InfluenceEntry::fact).toList(), destinationOwner);
        ReasonCode reason = refused ? ReasonCode.INFLUENCE_DENIED : ReasonCode.OK;
        if (TRACE.isInfoEnabled()) {
            TRACE.info(decisionLine(receiver, "public-write", reason, influence));
        }
        return reason;
    }

    /**
     * Whether only trusted content shaped this request, so that what it asks may be written into a trusted record:
     * a record later decisions take as fact, such as who holds a card, and which {@link #decide} would then take as
     * a destination owner. {@link #decide} cannot answer this, since it judges whose private data a write carries,
     * and a record written at the behest of untrusted text carries none: a hijacked model's charge would register
     * its own card to whoever it names. True only inside a scope whose chain verified at this hop, so that the
     * influence is the one the caller vouched for, and only when that influence holds no {@code third-party} and
     * no {@code local-untrusted} entry. Logs one {@code PAZTPORT_TRACE decision} line with
     * {@code rule=trusted-record}.
     */
    public boolean shapedOnlyByTrusted() {
        List<InfluenceEntry> influence = PaztportContext.influence();
        boolean trusted = PaztportContext.isOpen() && PaztportContext.verifiedChain() != null
                && influence.stream().noneMatch(e -> e.cls() == InfluenceClass.THIRD_PARTY
                        || e.cls() == InfluenceClass.LOCAL_UNTRUSTED);
        if (TRACE.isInfoEnabled()) {
            TRACE.info(decisionLine(receiver, "trusted-record", trusted ? ReasonCode.OK : ReasonCode.INFLUENCE_DENIED,
                    influence));
        }
        return trusted;
    }

    /**
     * {@code PAZTPORT_TRACE decision rid=… receiver=… rule=… reason=… ✓|✗ classes=…}, for this rule and the partner's
     * unsafe-session gate. The rid is the verified chain's, else the inbound chain's, else {@code -}. It comes from
     * the request, so it goes through {@link LogSafe}, as do the receiver and the classes.
     */
    static String decisionLine(String receiver, String rule, ReasonCode reason, List<InfluenceEntry> influence) {
        List<StampV3> chain = PaztportContext.verifiedChain() != null
                ? PaztportContext.verifiedChain() : PaztportContext.inboundChain();
        String rid = chain == null || chain.isEmpty() || chain.get(0).rid().isEmpty()
                ? "-" : LogSafe.of(chain.get(0).rid());
        TreeSet<String> classes = new TreeSet<>();
        influence.forEach(e -> classes.add(e.cls().wire()));
        return String.format("PAZTPORT_TRACE decision rid=%s receiver=%s rule=%s reason=%s %s classes=%s",
                rid, LogSafe.of(receiver), rule, reason, reason == ReasonCode.OK ? "✓" : "✗",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }
}
