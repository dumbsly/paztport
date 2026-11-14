// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.offline.Signers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * The checks the live and the offline chain verifiers share, each written once, numbered as the spec's live order
 * (verification.md, The live order): 1 to 6 on the stamps, check 1 being {@link Chains#parse}; 8 on the last stamp;
 * 9a to 9c on the blocks; and 12 on the route, with the hand-over on OK. Internal, as the two verifiers sit in two
 * packages: callers choose the order and add their own checks (freshness, the peer, replay) around these. Each
 * verifier also judges here, once and at its own time, which pinned keyrings and roots are current, and hands only
 * those to the checks; the event verifier shares the keyrings' lookup. Nothing here reads an item: what an item means
 * is its extension's to say.
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
     * Checks 1 to 6: the chain reads (CHAIN_MISSING), the origin is allowed (BAD_ORIGIN), each stamp is signed under
     * one of the keys {@code keyrings}, the current ones, give its service ({@link #keysFor}) and links to the one
     * before (BAD_SIGNATURE, BROKEN_LINK), then each stamp's {@code rcv} addresses the next stamp's service, bare or
     * with {@code #} and an operation name, and the last's names the receiver exactly (BINDING_MISMATCH), every stamp
     * carries the rid (RID_MISMATCH) and the session (SESSION_UNKNOWN). With {@code signers}, a stamp from another
     * service or instance than expected is not one the expected key signed: BAD_ORIGIN for the origin's instance,
     * BAD_SIGNATURE for any other. The result carries the stamps, or the first failure.
     */
    public static ParsedChain checkStamps(String value, List<Keyring> keyrings, Set<String> allowedOrigins,
            String sess, Shape shape) {
        // 1. The chain reads.
        ParsedChain parsed = Chains.parse(value);
        if (!parsed.ok()) {
            return parsed;
        }
        List<Stamp> stamps = parsed.stamps();
        Stamp first = stamps.get(0);
        Signers signers = shape.signers();

        // 2. Origin.
        if (!allowedOrigins.contains(first.svc()) || (signers != null && !first.inst().equals(signers.inst()))) {
            return fail(ReasonCode.BAD_ORIGIN);
        }

        // 3. Signatures and links.
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
        // 4. Only after the whole chain's signatures, the receivers: each stamp addresses the next stamp's service,
        // with an operation if it names one, and the last names the chain's receiver exactly.
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

    /** Check 8 alone: the last stamp binds what was received (BINDING_MISMATCH); null when it does. */
    public static ReasonCode checkBinding(Stamp last, String expectedBind) {
        return last.bind().equals(expectedBind) ? null : ReasonCode.BINDING_MISMATCH;
    }

    /** What checks 9a to 9c give: the blocks, one per stamp, or the first failure, and then no blocks. */
    public record BlocksCheck(List<Block> blocks, ReasonCode failure) {

        /** The blocks are copied; a failure carries none. */
        public BlocksCheck {
            blocks = blocks == null ? null : List.copyOf(blocks);
        }

        static BlocksCheck fail(ReasonCode code) {
            return new BlocksCheck(null, code);
        }
    }

    /**
     * Check 9a alone, written once for the verifiers and for a service that serves a request unverified: the blocks
     * read ({@link #readBlocks}), one per stamp, each block's commitment equal to its stamp's {@code ext}, compared as
     * text and never decoded. The result carries the blocks, or EXTENSION_MISMATCH.
     */
    public static BlocksCheck checkMatch(List<Stamp> stamps, String blocks) {
        List<Block> read;
        try {
            read = readBlocks(blocks);
        } catch (IllegalArgumentException e) {
            return BlocksCheck.fail(ReasonCode.EXTENSION_MISMATCH);
        }
        if (read == null) {
            read = Collections.nCopies(stamps.size(), Block.EMPTY);
        }
        if (read.size() != stamps.size()) {
            return BlocksCheck.fail(ReasonCode.EXTENSION_MISMATCH);
        }
        for (int i = 0; i < read.size(); i++) {
            if (!read.get(i).commit().equals(stamps.get(i).ext())) {
                return BlocksCheck.fail(ReasonCode.EXTENSION_MISMATCH);
            }
        }
        return new BlocksCheck(read, null);
    }

    /**
     * The blocks text received, read as an array of blocks; null when none was received. Text that reads as JSON
     * {@code null}, or as anything but an array of blocks, is refused.
     *
     * @throws IllegalArgumentException the text is not an array of blocks
     */
    public static List<Block> readBlocks(String blocks) {
        return blocks == null ? null : Block.parseAll(blocks);
    }

    /**
     * Checks 9a and 9b, then 9c when {@code requires} is true (spec verification.md, The live order):
     * <ul>
     * <li>9a: {@code blocks}, the JSON text received, reads as an array of blocks ({@link Block#parseAll}) with one
     *     block per stamp, and each block's commitment equals its stamp's {@code ext}, compared as text and never
     *     decoded. Null, no text received, is one empty block per stamp; text that reads as JSON {@code null} is not
     *     an array of blocks (EXTENSION_MISMATCH);
     * <li>9b: when the settings' allowed list is set, every name in any block's {@code items} or {@code requires} is
     *     in it (EXTENSION_NOT_ALLOWED);
     * <li>9c: every name in the last block's {@code requires} is one the service acts on (EXTENSION_REQUIRED): only
     *     the direct caller's requirements bind.
     * </ul>
     * 9a runs first, so every name 9b and 9c read is one its block's signer committed to.
     */
    public static BlocksCheck checkBlocks(List<Stamp> stamps, String blocks, ExtensionSettings settings,
            boolean requires) {
        // 9a. The blocks read, one per stamp, each matching its stamp's ext.
        BlocksCheck matched = checkMatch(stamps, blocks);
        if (matched.failure() != null) {
            return matched;
        }
        List<Block> read = matched.blocks();

        // 9b. Every name is one the verifier carries.
        for (Block b : read) {
            if (!b.names().stream().allMatch(settings::carries) || !b.requires().stream().allMatch(settings::carries)) {
                return BlocksCheck.fail(ReasonCode.EXTENSION_NOT_ALLOWED);
            }
        }

        // 9c. Every name the direct caller requires is acted on.
        if (requires && !settings.actsOn().containsAll(read.get(read.size() - 1).requires())) {
            return BlocksCheck.fail(ReasonCode.EXTENSION_REQUIRED);
        }
        return new BlocksCheck(read, null);
    }

    /**
     * Check 12 and the result: the route {@link Chains#route} gives, the first service then each {@code rcv}, the
     * last left off unless {@code receiverInRoute}, proven against one of {@code roots}, the current ones, that has the
     * proof's {@code rootId} (PATH_NOT_ALLOWED). Both outcomes name the last stamp; the caller decides whether that
     * name is kept. On OK the result holds the hand-over, verified: for each name the settings act on, one entry per
     * stamp of its block's items under it.
     */
    public static VerifyResult checkRoute(List<Stamp> stamps, boolean receiverInRoute, String proof,
            List<PinnedRoot> roots, List<Block> blocks, ExtensionSettings settings) {
        Stamp last = stamps.get(stamps.size() - 1);
        if (!provesPath(proof, Chains.route(stamps, receiverInRoute), roots)) {
            return new VerifyResult(ReasonCode.PATH_NOT_ALLOWED, last.svc(), last.inst(), null);
        }
        return new VerifyResult(ReasonCode.OK, last.svc(), last.inst(), new HandOver(true, stamps, blocks, settings));
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
