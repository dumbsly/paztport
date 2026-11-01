// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.List;
import java.util.Objects;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;

/**
 * Verifies a chain received live: the checks of the live order, the first failure being the result. Every
 * branch fails closed, and {@link #verify} never throws on malformed input; it is a typed rejection.
 *
 * <p>Check 0, before any stamp work: {@code policyNotAfter} is a window, an integer in [0, 2^53 &minus; 1], and the
 * clock has not passed it (POLICY_EXPIRED). It is about the verifier's own configuration, not the request, so it
 * comes first: past that moment the keyring and root no longer say which keys and routes the policy owner allows,
 * and no later check means anything against them. It names no suspect, not even a peer, because expiry is not the
 * sender's fault; a responder acting on it would quarantine every honest caller. {@link VerifierConfig#pinned}
 * only ever records a window it read from signed material, which is in range; a config built directly with one out
 * of range (2^53 would otherwise be a window that never closes) is refused here, per request, rather than by the
 * constructor, so that it fails exactly as the TypeScript verifier does and as the spec's check 0 says, and one
 * vector pins the answer for both.
 *
 * <ol>
 * <li>the stamps parse, every stamp's {@code v} is 3 (CHAIN_MISSING);
 * <li>no signed field holds {@code |}, {@code rcv} included (BAD_SIGNATURE);
 * <li>the origin's service is allowed (BAD_ORIGIN);
 * <li>each stamp is signed by its service's key and links to the one before, then each {@code rcv} names the
 *     next stamp's service and the last names the receiver (BAD_SIGNATURE, BROKEN_LINK, BINDING_MISMATCH);
 * <li>every stamp carries the origin's rid (RID_MISMATCH);
 * <li>every stamp is in the session (SESSION_UNKNOWN);
 * <li>the last stamp is within the call window of now and the origin within the run's lifetime (EXPIRED);
 * <li>the last stamp binds {@code expectedBind} (BINDING_MISMATCH);
 * <li>and commits to the influence (INFLUENCE_MISMATCH);
 * <li>its nonce key is new to the cache (REPLAY);
 * <li>the route is proven against the root (PATH_NOT_ALLOWED);
 * <li>with a peer, the peer's service is the last signer (PEER_MISMATCH).
 * </ol>
 *
 * <p>Attribution: with a peer, every result of checks 1 to 12 names it, because the transport authenticated that
 * sender whatever the chain says. Without one, only OK and PATH_NOT_ALLOWED name the last stamp, since by then
 * the signatures, receivers, times, binding and replay checks held; any earlier name would be unsigned, or belong
 * to a replayed or forwarded capture.
 */
public final class Verifier {

    private static final String NO_INFLUENCE = "[]";

    private final VerifierConfig cfg;

    public Verifier(VerifierConfig cfg) {
        this.cfg = Objects.requireNonNull(cfg, "cfg");
    }

    /**
     * How long the replay cache remembers a nonce key. A host that builds the verifier can check it against the
     * call window: below twice {@code callMaxAgeMs} every check fails closed as {@code REPLAY}.
     */
    public long nonceTtlMs() {
        return cfg.nonces().ttlMs();
    }

    /** The call freshness window, which bounds how short the replay cache's memory may be. */
    public long callMaxAgeMs() {
        return cfg.callMaxAgeMs();
    }

    /**
     * Runs the live order. The checks are total on malformed input, so a rejection is always a typed result;
     * a fault in what the verifier was given (a nonce cache or clock that throws) is not input and propagates,
     * rather than being hidden as a rejection.
     */
    public VerifyResult verify(VerifyInput in) {
        long now = cfg.clock().getAsLong();
        // 0. The pinned policy is still vouched for; first, and blaming no one (see the class comment).
        if (!JsonIntegers.inRange(cfg.policyNotAfter()) || now > cfg.policyNotAfter()) {
            return VerifyResult.reject(ReasonCode.POLICY_EXPIRED);
        }
        if (in == null) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }
        VerifyResult result = check(in, now);
        Peer peer = in.peer();
        return peer == null ? result : new VerifyResult(result.reason(), peer.svc(), peer.inst());
    }

    private VerifyResult check(VerifyInput in, long now) {
        // 1-6. Parse, delimiter, origin, signatures and links, then receivers, shared rid, session.
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), cfg.keyring(), cfg.allowedOrigins(), cfg.sess(),
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

        // 8-9. Binding and influence commitment.
        ReasonCode commitment = ChainChecks.checkCommitments(last, in.expectedBind(),
                in.influence() == null ? NO_INFLUENCE : in.influence());
        if (commitment != null) {
            return VerifyResult.reject(commitment);
        }

        // 10. Replay. A cache that forgets sooner than twice the call window fails closed, before spending the nonce.
        long ttl = cfg.nonces().ttlMs();
        if (in.nonceKey() == null || ttl < 0 || Math.floorDiv(ttl, 2) < cfg.callMaxAgeMs()
                || cfg.nonces().seenBefore(in.nonceKey(), now)) {
            return VerifyResult.reject(ReasonCode.REPLAY);
        }

        // 11. Route proven against the root, ending at the receiver only when it is on the route.
        VerifyResult routed = ChainChecks.checkRoute(stamps, in.receiverInRoute() ? in.receiver() : null,
                in.proof(), cfg.root(), cfg.rootId());
        if (!routed.ok()) {
            return routed;
        }

        // 12. The transport peer is the last signer.
        if (in.peer() != null && !in.peer().svc().equals(last.svc())) {
            return VerifyResult.reject(ReasonCode.PEER_MISMATCH);
        }
        return routed;
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
