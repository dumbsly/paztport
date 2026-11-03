// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.VerifyResult;

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live verifier's
 * checks in the live order. The first failure is the result:
 *
 * <ul>
 * <li>1 to 6: as the live verifier (CHAIN_MISSING, BAD_SIGNATURE, BAD_ORIGIN, BROKEN_LINK, BINDING_MISMATCH,
 *     RID_MISMATCH, SESSION_UNKNOWN), against the record's rid and, when given, the expected signers;
 * <li>7: in place of freshness, which has no clock to be fresh against offline, the last stamp's time is the
 *     one recorded with it (a record with no recorded time fails) and the origin's is one of the run's recorded
 *     times (TIME_MISMATCH); the last stamp is within the run's lifetime of the origin and the origin within the
 *     call window after it (EXPIRED), each limit the configuration's or, where it gives none, its live default;
 *     then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
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

    private static final String NO_INFLUENCE = "[]";

    private OfflineVerifier() {
    }

    /**
     * Runs the offline order. Malformed input is a typed rejection; a fault in what the verifier was given (a null
     * config, a read-only {@code seen} set) is not input and propagates.
     */
    public static OfflineResult verify(OfflineInput in, OfflineConfig cfg) {
        Objects.requireNonNull(cfg, "cfg");
        if (in == null) {
            return rejected(ReasonCode.CHAIN_MISSING);
        }
        // 1-6.
        ChainChecks.Shape shape = new ChainChecks.Shape(in.receiver(), in.rid(), cfg.signers());
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), cfg.keyring(), cfg.allowedOrigins(), cfg.sess(),
                shape);
        if (!parsed.ok()) {
            return rejected(parsed.failure());
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp first = stamps.get(0);
        Stamp last = stamps.get(stamps.size() - 1);

        // 7. Recorded times, the age limits, then the prompt.
        RecordedTimes t = in.recordedTs();
        if (t == null || last.ts() != t.last() || (t.run() != null && !t.run().contains(first.ts()))) {
            return result(ReasonCode.TIME_MISMATCH);
        }
        if (!withinAge(first.ts(), last.ts(), cfg)) {
            return result(ReasonCode.EXPIRED);
        }
        if (in.prompt() == null || !Text.isWellFormed(in.prompt())
                || !first.bind().equals(Bindings.prompt(in.prompt()))) {
            return result(ReasonCode.PROMPT_MISMATCH);
        }

        // 8-9. Binding and influence commitment.
        ReasonCode commitment = ChainChecks.checkCommitments(last, in.expectedBind(),
                in.influence() == null ? NO_INFLUENCE : in.influence());
        if (commitment != null) {
            return result(commitment);
        }

        // 10. Replay across the whole record set. A chain with no nonce key cannot be shown unspent.
        Set<String> seen = cfg.seen();
        if (in.nonceKey() == null || seen.contains(in.nonceKey())) {
            return result(ReasonCode.REPLAY);
        }
        seen.add(in.nonceKey());

        // 11. Route proven against the root.
        VerifyResult routed = ChainChecks.checkRoute(stamps, in.receiverInRoute() ? in.receiver() : null,
                in.proof(), cfg.root(), cfg.rootId());
        return new OfflineResult(routed.reason(), routed.suspectSvc(), routed.suspectInst());
    }

    /**
     * Check 7's age limits in exact longs, so an extreme time is EXPIRED rather than a wrapped difference. A limit
     * the configuration leaves null is its live default, independently of the other.
     */
    private static boolean withinAge(long firstTs, long lastTs, OfflineConfig cfg) {
        long runMax = cfg.runMaxAgeMs() == null ? VerifierConfig.RUN_MAX_AGE_MS : cfg.runMaxAgeMs();
        long callMax = cfg.callMaxAgeMs() == null ? VerifierConfig.CALL_MAX_AGE_MS : cfg.callMaxAgeMs();
        try {
            return Math.subtractExact(lastTs, firstTs) <= runMax
                    && Math.subtractExact(firstTs, lastTs) <= callMax;
        } catch (ArithmeticException e) {
            return false;
        }
    }

    private static OfflineResult result(ReasonCode reason) {
        return new OfflineResult(reason, "", "");
    }

    private static OfflineResult rejected(ReasonCode reason) {
        return result(reason);
    }
}
