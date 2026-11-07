// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.Influence;
import org.paztport.core.offline.Signers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * The checks the live and the offline chain verifiers share, each written once: 3 to 6 on the stamps, 8 and 9
 * on the last stamp, and 11 on the route. Checks 1 and 2 are {@link Chains#parse}. Internal, as the two
 * verifiers sit in two packages: callers choose the order and add their own checks (freshness, replay, the peer)
 * around these. Each verifier also judges here, once and at its own time, which pinned keyrings and roots are
 * current, and hands only those to the checks; the event verifier shares the keyrings' lookup.
 */
public final class ChainChecks {

    private ChainChecks() {
    }

    /**
     * A copy of the pinned {@code members} a config holds, refusing none ({@link IllegalArgumentException}) and a
     * null one ({@link NullPointerException}), each naming the list as {@code name}, so no check meets either.
     */
    public static <T> List<T> members(List<T> members, String name) {
        Objects.requireNonNull(members, name);
        if (members.isEmpty()) {
            throw new IllegalArgumentException(name + " is empty: pin at least one");
        }
        for (int i = 0; i < members.size(); i++) {
            Objects.requireNonNull(members.get(i), name + "[" + i + "]");
        }
        return List.copyOf(members);
    }

    /**
     * Whether a member pinned until {@code notAfter} is current at {@code at}: its window is a protocol integer, or
     * {@link Long#MAX_VALUE} for none, and {@code at} has not passed it. Any other window is current at no time.
     */
    private static boolean current(long notAfter, long at) {
        return (notAfter == Long.MAX_VALUE || JsonIntegers.inRange(notAfter)) && at <= notAfter;
    }

    /** The keys of the keyrings current at {@code at}, in their order. */
    public static List<Keyring> currentKeyrings(List<PinnedKeyring> keyrings, long at) {
        return keyrings.stream().filter(k -> current(k.notAfter(), at)).map(PinnedKeyring::keys).toList();
    }

    /** The roots current at {@code at}, in their order. */
    public static List<PinnedRoot> currentRoots(List<PinnedRoot> roots, long at) {
        return roots.stream().filter(r -> current(r.notAfter(), at)).toList();
    }

    /**
     * The keys {@code keyrings} give {@code svc}, looked up by its own name in each, each distinct key once (compared
     * by its encoding), so a key two keyrings share is tried once. Empty when none has a key for it.
     */
    public static List<PublicKey> keysFor(List<Keyring> keyrings, String svc) {
        List<PublicKey> keys = new ArrayList<>();
        List<byte[]> encoded = new ArrayList<>();
        for (Keyring keyring : keyrings) {
            PublicKey key = keyring.keyFor(svc);
            if (key != null && encoded.stream().noneMatch(e -> Arrays.equals(e, key.getEncoded()))) {
                keys.add(key);
                encoded.add(key.getEncoded());
            }
        }
        return keys;
    }

    /**
     * What a verifier takes. {@code receiver} is what the last stamp's {@code rcv} must name; {@code rid} the one
     * every stamp must carry, the origin's when null; {@code signers}, when non-null, the services and instance a
     * one-process chain must come from.
     */
    public record Shape(String receiver, String rid, Signers signers) {

        public static Shape live(String receiver) {
            return new Shape(receiver, null, null);
        }
    }

    /**
     * Checks 1 to 6: the chain parses (CHAIN_MISSING) with no delimiter in a field (BAD_SIGNATURE), the origin is
     * allowed (BAD_ORIGIN), each stamp is signed under one of the keys {@code keyrings}, the current ones, give its
     * service ({@link #keysFor}) and links to the one before (BAD_SIGNATURE, BROKEN_LINK), then each stamp's
     * {@code rcv} addresses the next stamp's service, bare or with {@code #} and an operation name, and the last's
     * names the receiver exactly (BINDING_MISMATCH), every stamp carries the rid (RID_MISMATCH) and the session
     * (SESSION_UNKNOWN). With {@code signers}, a stamp from another service or instance than expected is not one the
     * expected key signed: BAD_ORIGIN for the origin's instance, BAD_SIGNATURE for any other. The result carries the
     * stamps, or the first failure.
     */
    public static ParsedChain checkStamps(String value, List<Keyring> keyrings, Set<String> allowedOrigins,
            String sess, Shape shape) {
        // 1-2. Parse, and no delimiter in any field.
        ParsedChain parsed = Chains.parse(value);
        if (!parsed.ok()) {
            return parsed;
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp first = stamps.get(0);
        Signers signers = shape.signers();

        // 3. Origin.
        if (!allowedOrigins.contains(first.svc()) || (signers != null && !first.inst().equals(signers.inst()))) {
            return fail(ReasonCode.BAD_ORIGIN);
        }

        // 4. Signatures and links.
        for (int i = 0; i < stamps.size(); i++) {
            Stamp s = stamps.get(i);
            if (keysFor(keyrings, s.svc()).stream().noneMatch(key -> signatureValid(key, s))
                    || (signers != null && (i >= signers.svcs().size() || !s.svc().equals(signers.svcs().get(i))
                            || !s.inst().equals(signers.inst())))) {
                return fail(ReasonCode.BAD_SIGNATURE);
            }
            if (!s.prev().equals(i == 0 ? "" : stamps.get(i - 1).sig())) {
                return fail(ReasonCode.BROKEN_LINK);
            }
        }
        // Then the receivers: each stamp addresses the next stamp's service, with an operation if it names one, and
        // the last names the chain's receiver exactly.
        for (int i = 0; i < stamps.size(); i++) {
            String rcv = stamps.get(i).rcv();
            boolean addressed = i + 1 < stamps.size() ? Chains.addressedTo(rcv, stamps.get(i + 1).svc())
                    : rcv.equals(shape.receiver());
            if (!addressed) {
                return fail(ReasonCode.BINDING_MISMATCH);
            }
        }

        // 5. Shared rid.
        String rid = shape.rid() != null ? shape.rid() : first.rid();
        for (Stamp s : stamps) {
            if (!s.rid().equals(rid)) {
                return fail(ReasonCode.RID_MISMATCH);
            }
        }

        // 6. Session.
        for (Stamp s : stamps) {
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

    private static boolean signatureValid(PublicKey key, Stamp s) {
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
    public static ReasonCode checkCommitments(Stamp last, String expectedBind, String influence) {
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
     * Check 11 and the result: the route {@link Chains#route} gives, the first service then each {@code rcv}, the
     * last left off unless {@code receiverInRoute}, proven against one of {@code roots}, the current ones, that has the
     * proof's {@code rootId} (PATH_NOT_ALLOWED). Both outcomes name the last stamp; the caller decides whether that
     * name is kept.
     */
    public static VerifyResult checkRoute(List<Stamp> stamps, boolean receiverInRoute, String proof,
            List<PinnedRoot> roots) {
        Stamp last = stamps.get(stamps.size() - 1);
        if (!provesPath(proof, Chains.route(stamps, receiverInRoute), roots)) {
            return new VerifyResult(ReasonCode.PATH_NOT_ALLOWED, last.svc(), last.inst());
        }
        return new VerifyResult(ReasonCode.OK, last.svc(), last.inst());
    }

    /**
     * Whether the proof proves the route against a root with the proof's {@code rootId}: only those are tried, a root
     * and its renewals sharing one. Any malformed proof is "not proven".
     */
    private static boolean provesPath(String proof, String route, List<PinnedRoot> roots) {
        try {
            MerkleProof p = MerkleProof.parse(proof);
            return roots.stream().anyMatch(r -> r.rootId().equals(p.rootId()) && p.verify(route, r.root()));
        } catch (RuntimeException e) {
            return false;
        }
    }
}
