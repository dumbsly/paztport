// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.Influence;
import org.paztport.core.offline.Signers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.Routes;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * The checks the live and the offline chain verifiers share, each written once: 3 to 6 on the stamps, 8 and 9
 * on the last stamp, and 11 on the route. Checks 1 and 2 are {@link Chains#parse}. Internal, as the two
 * verifiers sit in two packages: callers choose the order and add their own checks (freshness, replay, the peer)
 * around these.
 */
public final class ChainChecks {

    private ChainChecks() {
    }

    /**
     * What a verifier takes. {@code receiver} is what the last v3 stamp's {@code rcv} must name; {@code rid} the one
     * every stamp must carry, the origin's when null; {@code signers}, when non-null, the services and instance a
     * one-process chain must come from.
     */
    public record Shape(String receiver, String rid, Signers signers) {

        public static Shape live(String receiver) {
            return new Shape(receiver, null, null);
        }
    }

    /**
     * Checks 1 to 6: the chain parses (CHAIN_MISSING) with no delimiter in a field (BAD_SIGNATURE), the origin
     * is allowed (BAD_ORIGIN), each stamp is signed by its service's key and links to the one before
     * (BAD_SIGNATURE, BROKEN_LINK), then each stamp's {@code rcv} names the next stamp's service and the
     * last's names the receiver (BINDING_MISMATCH), every stamp carries the rid (RID_MISMATCH) and the session
     * (SESSION_UNKNOWN). With {@code signers}, a stamp from another service or instance than expected is not
     * one the expected key signed: BAD_ORIGIN for the origin's instance, BAD_SIGNATURE for any other. The
     * result carries the stamps, or the first failure.
     */
    public static ParsedChain checkStamps(String value, Keyring keyring, Set<String> allowedOrigins, String sess,
            Shape shape) {
        // 1-2. Parse, and no delimiter in any field.
        ParsedChain parsed = Chains.parse(value);
        if (!parsed.ok()) {
            return parsed;
        }
        List<StampV3> stamps = parsed.stamps();
        StampV3 first = stamps.get(0);
        Signers signers = shape.signers();

        // 3. Origin.
        if (!allowedOrigins.contains(first.svc()) || (signers != null && !first.inst().equals(signers.inst()))) {
            return fail(ReasonCode.BAD_ORIGIN);
        }

        // 4. Signatures and links.
        for (int i = 0; i < stamps.size(); i++) {
            StampV3 s = stamps.get(i);
            PublicKey key = keyring.keyFor(s.svc());
            if (key == null || !signatureValid(key, s)
                    || (signers != null && (i >= signers.svcs().size() || !s.svc().equals(signers.svcs().get(i))
                            || !s.inst().equals(signers.inst())))) {
                return fail(ReasonCode.BAD_SIGNATURE);
            }
            if (!s.prev().equals(i == 0 ? "" : stamps.get(i - 1).sig())) {
                return fail(ReasonCode.BROKEN_LINK);
            }
        }
        // Then the receivers: each stamp names the next hop, and the last the chain's receiver.
        for (int i = 0; i < stamps.size(); i++) {
            String want = i + 1 < stamps.size() ? stamps.get(i + 1).svc() : shape.receiver();
            if (!stamps.get(i).rcv().equals(want)) {
                return fail(ReasonCode.BINDING_MISMATCH);
            }
        }

        // 5. Shared rid.
        String rid = shape.rid() != null ? shape.rid() : first.rid();
        for (StampV3 s : stamps) {
            if (!s.rid().equals(rid)) {
                return fail(ReasonCode.RID_MISMATCH);
            }
        }

        // 6. Session.
        for (StampV3 s : stamps) {
            if (!s.sess().equals(sess)) {
                return fail(ReasonCode.SESSION_UNKNOWN);
            }
        }
        return parsed;
    }

    /** A refusal carrying no stamps: the same record {@code ParsedChain.fail} makes for {@link Chains}. */
    private static ParsedChain fail(ReasonCode code) {
        return new ParsedChain(List.of(), code);
    }

    private static boolean signatureValid(PublicKey key, StampV3 s) {
        try {
            return Crypto.verify(key, s.signingBytes(), Base64Url.decode(s.sig()));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Checks 8 and 9: the last stamp binds what was expected (BINDING_MISMATCH) and commits to the influence
     * (INFLUENCE_MISMATCH). Null when both hold.
     */
    public static ReasonCode checkCommitments(StampV3 last, String expectedBind, String influence) {
        // 8. Binding.
        if (!last.bind().equals(expectedBind)) {
            return ReasonCode.BINDING_MISMATCH;
        }
        // 9. Influence commitment.
        String committed;
        try {
            committed = Influence.commit(Influence.parse(influence));
        } catch (IllegalArgumentException e) {
            return ReasonCode.INFLUENCE_MISMATCH;
        }
        return last.infl().equals(committed) ? null : ReasonCode.INFLUENCE_MISMATCH;
    }

    /**
     * Check 11 and the result: the chain's services, then the receiver when given, proven against the root
     * (PATH_NOT_ALLOWED). Both outcomes name the last stamp; the caller decides whether that name is kept.
     */
    public static VerifyResult checkRoute(List<StampV3> stamps, String receiver, String proof, byte[] root,
            String rootId) {
        StampV3 last = stamps.get(stamps.size() - 1);
        List<String> hops = new ArrayList<>(stamps.stream().map(StampV3::svc).toList());
        if (receiver != null) {
            hops.add(receiver);
        }
        if (!provesPath(proof, Routes.join(hops), root, rootId)) {
            return new VerifyResult(ReasonCode.PATH_NOT_ALLOWED, last.svc(), last.inst());
        }
        return new VerifyResult(ReasonCode.OK, last.svc(), last.inst());
    }

    /** Whether the proof names this root and proves the route against it; any malformed proof is "not proven". */
    private static boolean provesPath(String proof, String route, byte[] root, String rootId) {
        try {
            MerkleProof p = MerkleProof.parse(proof);
            return p.rootId().equals(rootId) && p.verify(route, root);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
