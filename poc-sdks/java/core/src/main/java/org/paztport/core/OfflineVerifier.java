// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live v3 verifier's
 * checks in the live order. A chain recorded before stamps bound their receiver, all v2, is taken as legacy and
 * has no receiver checks; a chain mixing versions is CHAIN_MISSING. The first failure is the result:
 *
 * <ul>
 * <li>1 to 6: as the live verifier (CHAIN_MISSING, BAD_SIGNATURE, BAD_ORIGIN, BROKEN_LINK, BINDING_MISMATCH,
 *     RID_MISMATCH, SESSION_UNKNOWN), against the record's rid and, when given, the expected signers;
 * <li>7: in place of freshness, which has no clock to be fresh against offline, the last stamp's time is the
 *     one recorded with it and the origin's is one of the run's recorded times (TIME_MISMATCH); with age limits,
 *     the last stamp is within the run's lifetime of the origin and the origin within the call window after it
 *     (EXPIRED); then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
 * <li>8 and 9: the last stamp binds {@code expectedBind} and commits to the influence;
 * <li>10: its nonce key has not been spent anywhere in the record set (REPLAY), which a live cache that
 *     forgets after its window cannot show;
 * <li>11: the route is proven against the root (PATH_NOT_ALLOWED).
 * </ul>
 *
 * <p>Checks 1 to 6, 8, 9 and 11 are {@link ChainChecks}, the live verifier's own code. There is no peer: a record
 * has no transport. {@link #verify} never throws on malformed input; it is a typed rejection.
 */
public final class OfflineVerifier {

    private static final JsonNode NO_INFLUENCE = JsonNodeFactory.instance.arrayNode();

    private OfflineVerifier() {
    }

    public static OfflineResult verify(OfflineInput in, OfflineConfig cfg) {
        Objects.requireNonNull(cfg, "cfg");
        if (in == null) {
            return rejected(ReasonCode.CHAIN_MISSING);
        }
        // 1-6.
        ChainChecks.Shape shape = new ChainChecks.Shape(true, in.receiver(), in.rid(), cfg.signers());
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), cfg.keyring(), cfg.allowedOrigins(), cfg.sess(),
                shape);
        if (!parsed.ok()) {
            return rejected(parsed.failure());
        }
        boolean legacy = parsed.legacy();
        List<RecordedStamp> stamps = parsed.stamps();
        RecordedStamp first = stamps.get(0);
        RecordedStamp last = stamps.get(stamps.size() - 1);

        // 7. Recorded times, the age limits, then the prompt.
        RecordedTimes t = in.recordedTs();
        if (t != null && (last.ts() != t.last() || (t.run() != null && !t.run().contains(first.ts())))) {
            return result(ReasonCode.TIME_MISMATCH, legacy);
        }
        if ((cfg.runMaxAgeMs() != null || cfg.callMaxAgeMs() != null) && !withinAge(first.ts(), last.ts(), cfg)) {
            return result(ReasonCode.EXPIRED, legacy);
        }
        if (in.prompt() == null || !first.bind().equals(Bindings.prompt(in.prompt()))) {
            return result(ReasonCode.PROMPT_MISMATCH, legacy);
        }

        // 8-9. Binding and influence commitment.
        ReasonCode commitment = ChainChecks.checkCommitments(last, in.expectedBind(),
                in.influence() == null ? NO_INFLUENCE : in.influence());
        if (commitment != null) {
            return result(commitment, legacy);
        }

        // 10. Replay across the whole record set. A chain with no nonce key cannot be shown unspent.
        Set<String> seen = cfg.seen();
        if (in.nonceKey() == null || seen.contains(in.nonceKey())) {
            return result(ReasonCode.REPLAY, legacy);
        }
        seen.add(in.nonceKey());

        // 11. Route proven against the root.
        VerifyResult routed = ChainChecks.checkRoute(stamps, in.receiverInRoute() ? in.receiver() : null,
                in.proof(), cfg.root(), cfg.rootId());
        return new OfflineResult(routed.reason(), routed.suspectSvc(), routed.suspectInst(), legacy);
    }

    /** Check 7's age limits in exact longs, so an extreme time is EXPIRED rather than a wrapped difference. */
    private static boolean withinAge(long firstTs, long lastTs, OfflineConfig cfg) {
        if (cfg.runMaxAgeMs() == null || cfg.callMaxAgeMs() == null) {
            return false;
        }
        try {
            return Math.subtractExact(lastTs, firstTs) <= cfg.runMaxAgeMs()
                    && Math.subtractExact(firstTs, lastTs) <= cfg.callMaxAgeMs();
        } catch (ArithmeticException e) {
            return false;
        }
    }

    private static OfflineResult result(ReasonCode reason, boolean legacy) {
        return new OfflineResult(reason, "", "", legacy);
    }

    private static OfflineResult rejected(ReasonCode reason) {
        return result(reason, false);
    }
}
