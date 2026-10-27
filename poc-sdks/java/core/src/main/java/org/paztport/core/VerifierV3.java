// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.List;
import java.util.Objects;

/**
 * Verifies a v3 chain received live: the twelve checks of the live order, the first failure being the result.
 * Every branch fails closed, and {@link #verify} never throws on malformed input; it is a typed rejection.
 *
 * <ol>
 * <li>the stamps parse, all v3 (CHAIN_MISSING);
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
 * <p>Attribution: with a peer, every result names it, because the transport authenticated that sender whatever
 * the chain says. Without one, only OK and PATH_NOT_ALLOWED name the last stamp, since by then the signatures,
 * receivers, times, binding and replay checks held; any earlier name would be unsigned, or belong to a replayed
 * or forwarded capture.
 */
public final class VerifierV3 {

    private static final JsonNode NO_INFLUENCE = JsonNodeFactory.instance.arrayNode();

    private final VerifierConfigV3 cfg;

    public VerifierV3(VerifierConfigV3 cfg) {
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
    public VerifyResult verify(VerifyInputV3 in) {
        if (in == null) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }
        VerifyResult result = check(in);
        Peer peer = in.peer();
        return peer == null ? result : new VerifyResult(result.reason(), peer.svc(), peer.inst());
    }

    private VerifyResult check(VerifyInputV3 in) {
        // 1-6. Parse, delimiter, origin, signatures and links, then receivers, shared rid, session.
        ParsedChain parsed = ChainChecks.checkStamps(in.stamps(), cfg.keyring(), cfg.allowedOrigins(), cfg.sess(),
                ChainChecks.Shape.live(in.receiver()));
        if (!parsed.ok()) {
            return VerifyResult.reject(parsed.failure());
        }
        List<RecordedStamp> stamps = parsed.stamps();
        RecordedStamp first = stamps.get(0);
        RecordedStamp last = stamps.get(stamps.size() - 1);

        // 7. Freshness: the call stamp is recent; the run (origin) is not too old nor from the future.
        long now = cfg.clock().getAsLong();
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
