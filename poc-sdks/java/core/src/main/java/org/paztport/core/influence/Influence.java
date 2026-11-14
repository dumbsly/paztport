// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.offline.RecordSet;
import org.paztport.core.offline.RecordedSession;
import org.paztport.core.stamp.Block;
import org.paztport.core.verify.HandOver.StampItems;
import org.paztport.core.verify.ReasonCode;

/**
 * The extension influence (spec influence.md), as functions over what the verifier hands on: the block a hop that
 * acts on it signs, the reading of the items it is handed and the decision on a guarded write, the entries a response
 * adds over HTTP, and a recorded call's result at a verifier that acts on it. The core never reads an item; what the
 * verifier hands on under {@link #NAME}, one {@link StampItems} per stamp in chain order, is read here. Also the
 * normalised order and the list form the blinded entries of {@link BoundaryInfluence} are built with.
 */
public final class Influence {

    /** The extension's name, under which its items travel in a block (spec influence.md). */
    public static final String NAME = "influence";

    private static final Comparator<String> OPTIONAL_FIRST_ABSENT =
            Comparator.nullsFirst(Comparator.<String>naturalOrder());

    /** Sorts by h, cls, src, cid, then owner (absent first); String order is by UTF-16 code unit. */
    private static final Comparator<InfluenceEntry> ORDER = Comparator
            .comparing(InfluenceEntry::h)
            .thenComparing(e -> e.cls().wire())
            .thenComparing(InfluenceEntry::src)
            .thenComparing(InfluenceEntry::cid, OPTIONAL_FIRST_ABSENT)
            .thenComparing(InfluenceEntry::owner, OPTIONAL_FIRST_ABSENT);

    private Influence() {
    }

    /**
     * What a service that acts on influence decides for a request.
     *
     * @param reason {@code OK}, {@code INFLUENCE_DENIED} or {@code INFLUENCE_MISMATCH}
     * @param everyStampNames whether every stamp handed on names influence; null when the reason is
     *        {@code INFLUENCE_MISMATCH}, since no rule was reached
     * @param unreadSigner the signer of the first block holding an item that does not read, for the operator's log,
     *        when the reason is {@code INFLUENCE_MISMATCH}; else null
     */
    public record Decision(ReasonCode reason, Boolean everyStampNames, String unreadSigner) {
    }

    /**
     * A request's block for a hop that acts on influence: it names influence with {@code entries}, as written, in the
     * order given; {@code []} names it with nothing to add, so it is not the empty block (spec influence.md, The
     * every-stamp rule).
     *
     * @param entries the entries the hop added itself for this request so far, never those it received
     * @throws IllegalArgumentException a name in {@code requires} that is not an extension name, or one twice
     */
    public static Block block(List<InfluenceEntry> entries, Collection<String> requires) {
        return Block.of(Map.of(NAME, entries.stream().map(InfluenceEntry::toJson).toList()), requires);
    }

    /**
     * Reads the items handed on under influence, one {@link StampItems} per stamp in chain order (spec influence.md,
     * The every-stamp rule and Entries): every item of every block, in order, each as an entry. A stamp whose items
     * are null is one whose block does not name influence. {@code stamps} null or empty is nothing handed on: there
     * is no stamp to read, so every stamp names it, and there are no entries.
     */
    public static RequestInfluence readRequest(List<StampItems> stamps) {
        List<InfluenceEntry> entries = new ArrayList<>();
        boolean everyStampNames = true;
        for (StampItems stamp : stamps == null ? List.<StampItems>of() : stamps) {
            if (stamp.items() == null) {
                everyStampNames = false;
                continue;
            }
            for (String item : stamp.items()) {
                try {
                    entries.add(InfluenceEntry.parse(item));
                } catch (IllegalArgumentException e) {
                    return new RequestInfluence(List.of(), false, stamp.svc());
                }
            }
        }
        return new RequestInfluence(entries, everyStampNames, null);
    }

    /**
     * What a service that acts on influence decides for a request (spec influence.md, What the rules read):
     * {@code INFLUENCE_MISMATCH} when an item handed on does not read; else, for a guarded public write,
     * {@code INFLUENCE_DENIED} when {@link InfluenceRule#guardedWriteRefused} refuses it over the entries handed on
     * plus {@code added}; else {@code OK}.
     *
     * @param stamps what the verifier handed on under influence, as {@link #readRequest} takes it
     * @param added the facts of what the service added itself, the responses to its own calls among them
     * @param guardedWrite whether the request writes to a public destination
     * @param destinationOwner the destination's owner, from the service's own trusted records; null when unknown
     */
    public static Decision decide(List<StampItems> stamps, Collection<InfluenceFact> added, boolean guardedWrite,
            String destinationOwner) {
        RequestInfluence read = readRequest(stamps);
        if (!read.reads()) {
            return new Decision(read.reason(), null, read.unreadSigner());
        }
        if (!guardedWrite) {
            return new Decision(ReasonCode.OK, read.everyStampNames(), null);
        }
        List<InfluenceFact> facts = new ArrayList<>(read.entries().stream().map(InfluenceEntry::fact).toList());
        facts.addAll(added);
        boolean refused = InfluenceRule.guardedWriteRefused(read.everyStampNames(), facts, destinationOwner);
        return new Decision(refused ? ReasonCode.INFLUENCE_DENIED : ReasonCode.OK, read.everyStampNames(), null);
    }

    /**
     * The entries a caller that acts on influence adds for one response over HTTP (spec influence.md, Content labels).
     * One entry per label, {@code {cls, src, h: resultHash, cid, owner}}, when {@code reason} is OK and the response's
     * block names influence with only labels under it; otherwise exactly one {@code local-untrusted} entry. Over HTTP
     * the response has one block, so only the response stamp's own entry is read.
     *
     * @param reason the response check's result; null where none ran
     * @param response the response stamp's own entry of the hand-over; null where there is none
     * @param src {@code http:<target>}, the caller's name for the service it sent the request to
     * @param resultHash the response's result hash, every entry's {@code h}
     * @throws IllegalArgumentException a null {@code src} or {@code resultHash}, which no entry can carry
     */
    public static List<InfluenceEntry> responseEntries(ReasonCode reason, StampItems response, String src,
            String resultHash) {
        List<InfluenceEntry> local = List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, src, resultHash,
                null, null));
        // a label counts only when the whole response verifies, so nothing is read from one that did not
        if (reason != ReasonCode.OK || response == null || response.items() == null) {
            return local;
        }
        List<InfluenceEntry> entries = new ArrayList<>();
        for (String item : response.items()) {
            try {
                entries.add(ContentLabel.parse(item).toEntry(src, resultHash));
            } catch (IllegalArgumentException e) {
                return local;
            }
        }
        return List.copyOf(entries);
    }

    /**
     * A verified record's reason at a verifier that acts on influence (spec verification.md, Offline verification,
     * row 9): {@code INFLUENCE_MISMATCH} when {@code result} is OK and an item handed on under influence does not
     * read, else {@code result}'s reason. A hand-over with nothing under influence, from a verifier that does not act
     * on it, is nothing handed on, and the result stands.
     */
    public static ReasonCode reason(OfflineResult result) {
        if (!result.ok()) {
            return result.reason();
        }
        RequestInfluence read = readRequest(result.handOver().under(NAME));
        return read.reads() ? result.reason() : read.reason();
    }

    /**
     * A recorded call's result in its session at a verifier that acts on influence: {@link #reason(OfflineResult)},
     * then the session's limits at {@code at}, the call's last stamp's {@code ts} ({@link RecordSet#callInSession}).
     * The item reading comes before {@code OUTSIDE_SESSION} (spec verification.md, Offline verification, row 9), so a
     * call past its session's limits that holds an item that does not read is {@code INFLUENCE_MISMATCH}. Null, as
     * {@link RecordSet#callInSession} gives it, for a session that is not attested at all.
     */
    public static ReasonCode recordedCallReason(OfflineResult result, RecordedSession session, long at) {
        return RecordSet.callInSession(session, reason(result), at);
    }

    /**
     * Reads an array of entries already read, each as {@link InfluenceEntry#parse} reads one: the list form the
     * originals of a {@link BoundaryInfluence.Opening} travel in.
     *
     * @throws IllegalArgumentException for a value that is not that
     */
    static List<InfluenceEntry> fromTree(JsonValue value) {
        List<InfluenceEntry> out = new ArrayList<>();
        for (JsonValue item : JsonFields.array(value)) {
            out.add(InfluenceEntry.fromTree(item));
        }
        return out;
    }

    /** Sorted copy with exact duplicates removed. An entry with an owner and one without are different. */
    public static List<InfluenceEntry> normalise(List<InfluenceEntry> entries) {
        List<InfluenceEntry> sorted = new ArrayList<>(entries);
        sorted.sort(ORDER);
        return new ArrayList<>(new LinkedHashSet<>(sorted));
    }

    /**
     * The entries as a JSON value, in the order given: the list form a {@link BoundaryInfluence} commitment hashes and
     * an opening's originals travel in.
     */
    static JsonValue.Arr tree(List<InfluenceEntry> entries) {
        return new JsonValue.Arr(entries.stream().map(e -> (JsonValue) e.tree()).toList());
    }
}
