// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import java.util.Collection;
import java.util.List;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;

/**
 * The extension intent's checks (spec intent.md, The receiver's part): the reading of the items handed on, and
 * whether the facts a handler requires are named. Comparing a fact with the request is the handler's.
 */
public final class Intent {

    /** The extension's name. */
    public static final String NAME = "intent";

    private Intent() {
    }

    /**
     * Reads the items handed on under intent, one {@link HandOver.StampItems} per stamp in chain order (check P1):
     * the first stamp's items are null, empty, or one item that reads as an intent item, and every later stamp's are
     * null or empty. Anything else is a request whose items do not read, naming that stamp's signer. {@code stamps}
     * null, as {@code HandOver.under} gives for a service that does not act on intent, reads as no facts.
     */
    public static RequestIntent readRequest(List<HandOver.StampItems> stamps) {
        if (stamps == null) {
            return new RequestIntent(IntentFacts.NONE, null);
        }
        IntentFacts facts = IntentFacts.NONE;
        for (int i = 0; i < stamps.size(); i++) {
            HandOver.StampItems stamp = stamps.get(i);
            List<String> items = stamp.items();
            if (items == null || items.isEmpty()) {
                continue;
            }
            if (i > 0 || items.size() > 1) {
                return new RequestIntent(IntentFacts.NONE, stamp.svc());
            }
            try {
                facts = IntentFacts.parse(items.get(0));
            } catch (IllegalArgumentException e) {
                return new RequestIntent(IntentFacts.NONE, stamp.svc());
            }
        }
        return new RequestIntent(facts, null);
    }

    /**
     * What a handler that requires the facts {@code needs} is answered (check P2, and spec intent.md, A request that
     * did not verify): {@code OK} when {@code needs} is empty, since the item check runs elsewhere. Otherwise
     * {@code INTENT_MISSING} when the hand-over is null, not verified, or does not hold intent, or a name is not
     * among the facts; {@code INTENT_MISMATCH} when the items do not read, which comes before a missing name.
     *
     * @param handOver what the verifier handed the service; null for none
     * @param needs the names of the facts the handler requires, from the service's own configuration
     */
    public static ReasonCode require(HandOver handOver, Collection<String> needs) {
        if (needs.isEmpty()) {
            return ReasonCode.OK;
        }
        if (handOver == null || !handOver.verified() || handOver.under(NAME) == null) {
            return ReasonCode.INTENT_MISSING;
        }
        RequestIntent read = readRequest(handOver.under(NAME));
        if (!read.reads()) {
            return read.reason();
        }
        for (String name : needs) {
            if (!read.facts().has(name)) {
                return ReasonCode.INTENT_MISSING;
            }
        }
        return ReasonCode.OK;
    }
}
