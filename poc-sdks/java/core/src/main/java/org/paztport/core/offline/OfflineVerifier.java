// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.policy.Keyring;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.VerifyResult;

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live verifier's
 * checks in the live order and the differences the spec's offline table gives (verification.md, Offline
 * verification). The first failure is the result:
 *
 * <ul>
 * <li>0: in place of the live window, some keyring and some root count for the record, their {@code notAfter} at
 *     or after its recorded time (POLICY_EXPIRED, naming no one); with no recorded time every one counts, and check
 *     7 refuses the record. The checks after it use only those that count;
 * <li>1 to 6: as the live verifier (CHAIN_MISSING, BAD_ORIGIN, BAD_SIGNATURE, BROKEN_LINK, BINDING_MISMATCH,
 *     RID_MISMATCH, SESSION_UNKNOWN), against the record's rid and, when given, the expected signers;
 * <li>7: in place of freshness, which has no clock to be fresh against offline, the last stamp's time is the
 *     one recorded with it (a record with no recorded time fails) and the origin's is one of the run's recorded
 *     times (TIME_MISMATCH); the last stamp is within the run's lifetime of the origin and the origin within the
 *     call window after it (EXPIRED), each limit the configuration's or, where it gives none, its live default;
 *     then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
 * <li>8: the last stamp binds {@code expectedBind} (BINDING_MISMATCH);
 * <li>9a and 9b: the blocks read, one per stamp, each matching its stamp's {@code ext} (EXTENSION_MISMATCH), and
 *     with an allowed list of the verifier's own every name is in it (EXTENSION_NOT_ALLOWED); 9c is live only, as
 *     a record does not hold the {@code actsOn} the call was held to;
 * <li>10: there is no peer offline, as a record has no transport;
 * <li>11: its nonce key has not been spent anywhere in the record set (REPLAY), which a live cache that
 *     forgets after its window cannot show;
 * <li>12: the route is proven against a root that counts, with the proof's {@code rootId} (PATH_NOT_ALLOWED).
 * </ul>
 *
 * <p>Checks 1 to 6, 8, 9a, 9b and 12 are {@link ChainChecks}, the live verifier's own code. On OK the result holds
 * the hand-over, verified, for the names the configuration acts on. {@link #verify} never throws on malformed
 * input; it is a typed rejection.
 */
public final class OfflineVerifier {

    /** The time a record with none is judged at for check 0: before every window, so every member counts. */
    private static final long NO_TIME = Long.MIN_VALUE;

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
        // 0. The keyrings and roots that count at the record's own time, once; none of either names no one.
        RecordedTimes t = in.recordedTs();
        long at = t == null ? NO_TIME : t.last();
        List<Keyring> keyrings = ChainChecks.currentKeyrings(cfg.keyrings(), at);
        List<PinnedRoot> roots = ChainChecks.currentRoots(cfg.roots(), at);
        if (keyrings.isEmpty() || roots.isEmpty()) {
            return rejected(ReasonCode.POLICY_EXPIRED);
        }

        // 1-6. The chain reads, origin, signatures and links, receivers, the record's rid, session.
        ChainChecks.Shape shape = new ChainChecks.Shape(in.receiver(), in.rid(), cfg.signers());
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), keyrings, cfg.allowedOrigins(), cfg.sess(), shape);
        if (!parsed.ok()) {
            return rejected(parsed.failure());
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp first = stamps.get(0);
        Stamp last = stamps.get(stamps.size() - 1);

        // 7. Recorded times, the age limits, then the prompt.
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

        // 8. Binding.
        ReasonCode bound = ChainChecks.checkBinding(last, in.expectedBind());
        if (bound != null) {
            return result(bound);
        }

        // 9a-9b. The blocks; 9c is live only.
        ChainChecks.BlocksCheck blocks = ChainChecks.checkBlocks(stamps, in.blocks(), cfg.extensions(), false);
        if (blocks.failure() != null) {
            return result(blocks.failure());
        }

        // 11. Replay across the whole record set. A chain with no nonce key cannot be shown unspent.
        Set<String> seen = cfg.seen();
        if (in.nonceKey() == null || seen.contains(in.nonceKey())) {
            return result(ReasonCode.REPLAY);
        }
        seen.add(in.nonceKey());

        // 12. Route proven against a root that counts for the record; on OK, the hand-over.
        VerifyResult routed = ChainChecks.checkRoute(stamps, in.receiverInRoute(), in.proof(), roots, blocks.blocks(),
                cfg.extensions());
        return new OfflineResult(routed.reason(), routed.suspectSvc(), routed.suspectInst(), routed.handOver());
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
        return new OfflineResult(reason, "", "", null);
    }

    private static OfflineResult rejected(ReasonCode reason) {
        return result(reason);
    }
}
