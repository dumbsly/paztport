// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.List;
import java.util.Objects;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;

/**
 * Verifies a chain received live: the checks of the live order (spec verification.md, The live order), the first
 * failure being the result. Every branch fails closed, and {@link #verify} never throws on malformed input; it is a
 * typed rejection.
 *
 * <p>Check 0, before any stamp work: {@code policyNotAfter} is a window, an integer in [0, 2^53 &minus; 1], and the
 * clock has not passed it (POLICY_EXPIRED). It is about the verifier's own configuration, not the request, so it
 * comes first: past that moment no keyring, or no root, says any longer which keys or routes the policy owner
 * allows, and no later check means anything against them. It names no suspect, not even a peer, because expiry is
 * not the sender's fault; a responder acting on it would quarantine every honest caller. {@link VerifierConfig#pinned}
 * only ever records a window it read from signed material, which is in range; a config built directly with one out
 * of range (2^53 would otherwise be a window that never closes) is refused here, per request, rather than by the
 * constructor, so that it fails exactly as the TypeScript verifier does and as the spec's check 0 says, and one
 * vector pins the answer for both. The checks after it use only the keyrings and roots current at the clock: those
 * whose {@code notAfter} it has not passed.
 *
 * <ol>
 * <li>the chain reads, as stamps each of {@link Stamp#VERSION} with exactly a stamp's members (CHAIN_MISSING);
 * <li>the origin's service is allowed (BAD_ORIGIN);
 * <li>each stamp is signed under one of the keys the current keyrings give its service, by its own name, and links
 *     to the one before (BAD_SIGNATURE, BROKEN_LINK);
 * <li>only then, each {@code rcv} but the last addresses the next stamp's service (bare, or {@code #} and an
 *     operation name) and the last names the receiver exactly (BINDING_MISMATCH);
 * <li>every stamp carries the origin's rid (RID_MISMATCH);
 * <li>every stamp is in the session (SESSION_UNKNOWN);
 * <li>the last stamp is within the call window of now and the origin within the run's lifetime (EXPIRED);
 * <li>the last stamp binds {@code expectedBind} (BINDING_MISMATCH);
 * </ol>
 * <ul>
 * <li>9a: the blocks read, one per stamp, each matching its stamp's {@code ext}; none received is one empty block
 *     per stamp (EXTENSION_MISMATCH);
 * <li>9b: with an allowed list, every name in any block is in it (EXTENSION_NOT_ALLOWED);
 * <li>9c: every name the last block requires is one the service acts on (EXTENSION_REQUIRED); {@link #verifyRecorded}
 *     leaves this one out;
 * <li>10: with a peer, the peer's service is the last signer (PEER_MISMATCH), so a request sent again by another
 *     peer spends no nonce key;
 * <li>11: its nonce key is new to the cache, which remembers keys for at least twice the call window (REPLAY);
 * <li>12: the route, each {@code rcv} after the origin's service with the last left off unless
 *     {@code receiverInRoute}, is proven against a current root with the proof's {@code rootId} (PATH_NOT_ALLOWED).
 * </ul>
 *
 * <p>On OK the result holds the hand-over ({@link HandOver}), verified: for each name the service acts on, one entry
 * per stamp. A refusal hands nothing over.
 *
 * <p>Attribution: with a peer, every result of checks 1 to 12 names it, because the transport authenticated that
 * sender whatever the chain says. Without one, only OK and PATH_NOT_ALLOWED name the last stamp, since by then
 * the signatures, receivers, times, binding, blocks and replay checks held; any earlier name would be unsigned, or
 * belong to a replayed or forwarded capture.
 */
public final class Verifier {

    private final VerifierConfig cfg;

    /** A verifier holding {@code cfg}, which it reads for every request; null is refused. */
    public Verifier(VerifierConfig cfg) {
        this.cfg = Objects.requireNonNull(cfg, "cfg");
    }

    /**
     * The extension settings this verifier's config holds: the names checks 9b and 9c read and its hand-over carries.
     * A transport reads them from here, so a service cannot verify under one {@code actsOn} and build its blocks or
     * read what it is handed under another.
     */
    public ExtensionSettings extensions() {
        return cfg.extensions();
    }

    /**
     * Runs the live order, 0 to 12. The checks are total on malformed input, so a rejection is always a typed
     * result; a fault in what the verifier was given (a clock that throws) is not input and propagates, rather than
     * being hidden as a rejection.
     *
     * @throws NonceCacheUnavailableException when the nonce cache throws at check 11, with its exception as the
     *     cause: the replay check then has no verdict, which is neither a rejection nor an acceptance
     */
    public VerifyResult verify(VerifyInput in) {
        return run(in, true);
    }

    /**
     * The live order without check 9c, for a response read back from a record (spec verification.md, Offline
     * verification): it was held to the caller's {@code actsOn} live, which a record does not hold. Every other
     * check, the nonce included, runs as in {@link #verify}.
     *
     * @throws NonceCacheUnavailableException as {@link #verify}
     */
    public VerifyResult verifyRecorded(VerifyInput in) {
        return run(in, false);
    }

    /** The live order; check 9c only when {@code requires}. */
    private VerifyResult run(VerifyInput in, boolean requires) {
        long now = cfg.clock().getAsLong();
        // 0. The pinned policy is still vouched for; first, and blaming no one (see the class comment).
        if (!JsonIntegers.inRange(cfg.policyNotAfter()) || now > cfg.policyNotAfter()) {
            return VerifyResult.reject(ReasonCode.POLICY_EXPIRED);
        }
        if (in == null) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }
        // The keyrings and roots current now, once for every check that follows.
        VerifyResult result = check(in, now, ChainChecks.currentKeyrings(cfg.keyrings(), now),
                ChainChecks.currentRoots(cfg.roots(), now), requires);
        Peer peer = in.peer();
        return peer == null ? result : new VerifyResult(result.reason(), peer.svc(), peer.inst(), result.handOver());
    }

    private VerifyResult check(VerifyInput in, long now, List<Keyring> keyrings, List<PinnedRoot> roots,
            boolean requires) {
        // 1-6. The chain reads, origin, signatures and links, then receivers, shared rid, session.
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), keyrings, cfg.allowedOrigins(), cfg.sess(),
                ChainChecks.Shape.live(in.receiver()));
        if (!parsed.ok()) {
            return VerifyResult.reject(parsed.failure());
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp first = stamps.get(0);
        Stamp last = stamps.get(stamps.size() - 1);

        // 7. Freshness: the call stamp is recent; the run (origin) is not too old nor from the future.
        if (!fresh(now, first.ts(), last.ts())) {
            return VerifyResult.reject(ReasonCode.EXPIRED);
        }

        // 8. Binding.
        ReasonCode bound = ChainChecks.checkBinding(last, in.expectedBind());
        if (bound != null) {
            return VerifyResult.reject(bound);
        }

        // 9a-9c. The blocks; 9c only live.
        ChainChecks.BlocksCheck blocks = ChainChecks.checkBlocks(stamps, in.blocks(), cfg.extensions(), requires);
        if (blocks.failure() != null) {
            return VerifyResult.reject(blocks.failure());
        }

        // 10. The transport peer is the last signer, before the nonce is spent.
        if (in.peer() != null && !in.peer().svc().equals(last.svc())) {
            return VerifyResult.reject(ReasonCode.PEER_MISMATCH);
        }

        // 11. Replay. A cache that forgets sooner than twice the call window fails closed, before spending the nonce.
        long ttl = cfg.nonces().ttlMs();
        if (in.nonceKey() == null || ttl < 0 || Math.floorDiv(ttl, 2) < cfg.callMaxAgeMs()
                || seenBefore(in.nonceKey(), now)) {
            return VerifyResult.reject(ReasonCode.REPLAY);
        }

        // 12. Route built from the stamps' rcv and proven against a current root; the receiver ends it only when it
        // is on the route. On OK, the hand-over.
        return ChainChecks.checkRoute(stamps, in.receiverInRoute(), in.proof(), roots, blocks.blocks(),
                cfg.extensions());
    }

    /**
     * The cache's answer; a cache that cannot give one has no verdict, which is not a rejection. Any exception is
     * caught, as a checked one can be thrown where the compiler cannot see it (from Kotlin, say).
     */
    private boolean seenBefore(String key, long now) {
        try {
            return cfg.nonces().seenBefore(key, now);
        } catch (Exception e) {
            throw new NonceCacheUnavailableException(e);
        }
    }

    /** Check 7's arithmetic, in exact longs so an extreme clock is EXPIRED rather than a wrapped difference. */
    private boolean fresh(long now, long firstTs, long lastTs) {
        try {
            long call = cfg.callMaxAgeMs();
            long run = cfg.runMaxAgeMs();
            long age = Math.subtractExact(now, lastTs);
            return age <= call && age >= -call
                    && Math.subtractExact(now, firstTs) <= run
                    && Math.subtractExact(firstTs, now) <= call;
        } catch (ArithmeticException e) {
            return false;
        }
    }
}
