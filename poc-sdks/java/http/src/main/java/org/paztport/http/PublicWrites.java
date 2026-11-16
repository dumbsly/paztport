// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.ArrayList;
import java.util.List;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.influence.InfluenceRule;
import org.paztport.core.influence.RequestInfluence;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.internal.DecisionLine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The rule for a guarded public write over the request's influence (spec influence.md, What the rules read), so that
 * service code asks one question before it writes somewhere its owner cannot vouch for: may what this request has
 * read go to this destination? It is {@link Influence#decide} over what the request was handed under influence
 * ({@link RequestContext#handedOn}) and the entries the service added ({@link RequestContext#added}): the answer is
 * {@link ReasonCode#INFLUENCE_DENIED} when a stamp handed on does not name influence, when an item handed on does not
 * read, or when untrusted content sits beside private content that is not the destination owner's, and
 * {@link ReasonCode#OK} otherwise.
 *
 * <p>The rules are those of a service that acts on {@code influence}, so a service whose settings do not act on it
 * ({@link RequestContext}'s, set by the receiver that served the request) is refused every guarded write and holds no
 * trusted record: a guard that read nothing there would hold vacuously, which is the deployment spec influence.md,
 * The every-stamp rule, names as the mistake.
 *
 * <p>The destination owner must come from the service's own records, never from request content, or the request
 * could name its own destination owner and pass. Outside a {@link RequestContext.Scope} there is no influence to
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
     * The rule for a guarded public write over the request in the context. What it was handed is verified only where
     * the request's chain verified at this hop. A request served without verifying (in audit mode after a failure, at
     * a hop that is off, or at a service that verifies no requests under a mode) is handed its items as not verified
     * where its chain read and its blocks passed check 9a, and the rule reads them too (spec influence.md, What the
     * rules read). Where nothing was handed on (at an origin, where the chain did not read, or in an unsafe partner
     * session) the rule reads only what the service added, and cannot refuse for content it is not shown: a partner
     * must therefore switch its public writes off for unsafe sessions ({@link UnsafeEndpoints}), so that an unsafe
     * session never reaches them (spec influence.md, What the rules read).
     *
     * @param destinationOwner the owner of the destination from trusted records, or null/empty when unknown
     * @return {@link ReasonCode#OK} or {@link ReasonCode#INFLUENCE_DENIED}, never another code: an item handed on that
     *     does not read denies the write (spec influence.md, The owner-aware rule)
     */
    public ReasonCode decide(String destinationOwner) {
        List<InfluenceEntry> added = RequestContext.added();
        HandOver handedOn = RequestContext.handedOn();
        List<HandOver.StampItems> stamps = handedOn == null ? null : handedOn.under(Influence.NAME);
        // Influence.decide gives INFLUENCE_MISMATCH where an item handed on does not read. The receiver refused such a
        // request at a service acting on influence, so only a hand-over set by hand reaches it here, and it is denied.
        boolean allowed = actsOnInfluence() && Influence.decide(stamps,
                added.stream().map(InfluenceEntry::fact).toList(), true, destinationOwner).reason() == ReasonCode.OK;
        ReasonCode reason = allowed ? ReasonCode.OK : ReasonCode.INFLUENCE_DENIED;
        if (TRACE.isInfoEnabled()) {
            TRACE.info(DecisionLine.of(receiver, "public-write", reason, shown(stamps, added).entries()));
        }
        return reason;
    }

    /** Whether a scope is open and the service serving it acts on {@code influence}. */
    private static boolean actsOnInfluence() {
        ExtensionSettings settings = RequestContext.extensions();
        return RequestContext.isOpen() && settings != null && settings.actsOn().contains(Influence.NAME);
    }

    /** What the request was handed under influence, read, beside what the service added. */
    private static RequestInfluence shown(List<HandOver.StampItems> stamps, List<InfluenceEntry> added) {
        RequestInfluence read = Influence.readRequest(stamps);
        if (!read.reads()) {
            return read;
        }
        List<InfluenceEntry> all = new ArrayList<>(read.entries());
        all.addAll(added);
        return new RequestInfluence(all, read.everyStampNames(), null);
    }

    /**
     * Whether only trusted content shaped this request, so that what it asks may be written into a trusted record:
     * a record later decisions take as fact, such as who holds a card, and which {@link #decide} would then take as
     * a destination owner. Never true at a service that does not act on {@code influence}. {@link #decide} cannot
     * answer this, since it judges whose private data a write carries,
     * and a record written at the behest of untrusted text carries none: a hijacked model's charge would register
     * its own card to whoever it names. True only inside a scope whose chain verified at this hop, so that the
     * influence is the one the caller vouched for; only when every item handed on reads and every stamp handed on
     * names influence, since a hop that does not may have read anything (spec influence.md, The every-stamp rule);
     * and only when what it was handed and what the service added hold no {@code third-party} and no
     * {@code local-untrusted} entry. Logs one {@code PAZTPORT_TRACE decision} line with {@code rule=trusted-record}.
     */
    public boolean shapedOnlyByTrusted() {
        HandOver handedOn = RequestContext.handedOn();
        RequestInfluence shown = shown(handedOn == null ? null : handedOn.under(Influence.NAME),
                RequestContext.added());
        boolean trusted = actsOnInfluence() && RequestContext.verifiedChain() != null && shown.reads()
                && shown.everyStampNames()
                && InfluenceRule.shapedOnlyByTrusted(shown.entries().stream().map(InfluenceEntry::fact).toList());
        if (TRACE.isInfoEnabled()) {
            TRACE.info(DecisionLine.of(receiver, "trusted-record",
                    trusted ? ReasonCode.OK : ReasonCode.INFLUENCE_DENIED, shown.entries()));
        }
        return trusted;
    }
}
