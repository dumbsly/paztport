// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import java.util.TreeSet;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.ReasonCode;

/**
 * The trace line that more than one part of the starter logs in the same form, so that operators and the demo read
 * one format wherever it comes from. It holds no state and is not for an application to use.
 */
final class TraceLines {

    private TraceLines() {
    }

    /**
     * {@code PAZTPORT_TRACE decision rid=… receiver=… rule=… reason=… ✓|✗ classes=…}, for the public-write rule
     * ({@link PublicWrites}) and the partner's unsafe-session gate. The rid is the verified chain's, else the inbound
     * chain's, else {@code -}. It comes from the request, so it goes through {@link LogSafe}, as do the receiver and
     * the classes.
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
