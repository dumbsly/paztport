// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;

class BoundaryInfluenceTest {

    private static final byte[] KEY = Crypto.sha256("boundary-influence-test-key".getBytes(StandardCharsets.UTF_8));
    private static final String RID = "rid-1";
    private static final String RCV = "psp";
    private static final String EGRESS = "payment";

    private static final InfluenceEntry ALICE_ORDER =
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-order", "alice");
    private static final InfluenceEntry ALICE_CARD =
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:cards", "h-card", null, "alice");
    private static final InfluenceEntry BOB_ORDER =
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-bob", null, "bob");
    private static final InfluenceEntry LEDGER =
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:ledger", "h-ledger", null, null);
    private static final InfluenceEntry TICKET =
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "h-ticket", "cid-ticket", null);
    private static final InfluenceEntry SCRIPT =
            new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "local:script", "h-script", null, null);
    private static final InfluenceEntry DOCS =
            new InfluenceEntry(InfluenceClass.PUBLIC, "web:example.com", "h-docs", null, null);

    private static List<InfluenceEntry> reduce(List<InfluenceEntry> entries) {
        return BoundaryInfluence.reduce(entries, KEY, RID, RCV, EGRESS);
    }

    private static Set<InfluenceFact> facts(List<InfluenceEntry> entries) {
        return entries.stream().map(InfluenceEntry::fact).collect(Collectors.toSet());
    }

    private static InfluenceEntry sentFor(List<InfluenceEntry> reduced, InfluenceClass cls, String owner) {
        return reduced.stream().filter(e -> e.cls() == cls && java.util.Objects.equals(e.owner(), owner))
                .findFirst().orElseThrow();
    }

    private static String salt(InfluenceClass cls, String owner) {
        return Base64Url.encode(BoundaryInfluence.salt(KEY, RID, RCV, cls, owner));
    }

    private static BoundaryInfluence.Opening opening(InfluenceClass cls, String owner, InfluenceEntry... originals) {
        return new BoundaryInfluence.Opening(cls, owner, salt(cls, owner), List.of(originals));
    }

    @Test
    void ruleVerdictUnchanged() {
        List<List<InfluenceEntry>> table = List.of(
                List.of(),
                List.of(ALICE_ORDER),
                List.of(ALICE_ORDER, TICKET),
                List.of(LEDGER, SCRIPT),
                List.of(DOCS),
                List.of(ALICE_ORDER, BOB_ORDER, TICKET));
        for (List<InfluenceEntry> influence : table) {
            List<InfluenceFact> reduced = reduce(influence).stream().map(InfluenceEntry::fact).toList();
            List<InfluenceFact> original = influence.stream().map(InfluenceEntry::fact).toList();
            for (String owner : Arrays.asList("alice", "bob", null)) {
                assertEquals(InfluenceRule.publicWriteRefused(original, owner),
                        InfluenceRule.publicWriteRefused(reduced, owner), influence + " to " + owner);
            }
        }
    }

    @Test
    void pairsPreserved() {
        List<InfluenceEntry> input = List.of(ALICE_ORDER, ALICE_CARD, BOB_ORDER, LEDGER, TICKET, SCRIPT, DOCS);
        List<InfluenceEntry> reduced = reduce(input);
        assertEquals(facts(input), facts(reduced));
        assertEquals(facts(input).size(), reduced.size(), "one entry per (cls, owner)");
        assertEquals(Influence.normalise(reduced), reduced, "the output is normalised");
    }

    @Test
    void ownerAndNoOwnerAreSeparateGroups() {
        InfluenceEntry owned = new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-1", null, "alice");
        InfluenceEntry unowned = new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-1", null, null);
        List<InfluenceEntry> reduced = reduce(List.of(owned, unowned));
        assertEquals(2, reduced.size());
        InfluenceEntry sentOwned = sentFor(reduced, InfluenceClass.PRIVATE, "alice");
        InfluenceEntry sentUnowned = sentFor(reduced, InfluenceClass.PRIVATE, null);
        BoundaryInfluence.Opening openOwned = opening(InfluenceClass.PRIVATE, "alice", owned);
        BoundaryInfluence.Opening openUnowned = opening(InfluenceClass.PRIVATE, null, unowned);
        assertTrue(BoundaryInfluence.opens(sentOwned, openOwned));
        assertTrue(BoundaryInfluence.opens(sentUnowned, openUnowned));
        assertFalse(BoundaryInfluence.opens(sentOwned, openUnowned));
        assertFalse(BoundaryInfluence.opens(sentUnowned, openOwned));
    }

    @Test
    void emptyGivesEmpty() {
        List<InfluenceEntry> reduced = reduce(List.of());
        assertTrue(reduced.isEmpty());
        assertEquals("", Influence.commit(reduced));
    }

    @Test
    void noSourcesOrHashesCross() {
        List<InfluenceEntry> input = List.of(ALICE_ORDER, ALICE_CARD, BOB_ORDER, LEDGER, TICKET, SCRIPT, DOCS);
        Set<String> originalHashes = input.stream().map(InfluenceEntry::h).collect(Collectors.toSet());
        for (InfluenceEntry e : reduce(input)) {
            assertEquals("boundary:" + EGRESS, e.src());
            assertFalse(originalHashes.contains(e.h()), e.h());
            assertNull(e.cid());
        }
    }

    @Test
    void sameContentDiffersPerRid() {
        List<InfluenceEntry> input = List.of(ALICE_ORDER, TICKET);
        List<InfluenceEntry> one = BoundaryInfluence.reduce(input, KEY, "rid-1", RCV, EGRESS);
        List<InfluenceEntry> two = BoundaryInfluence.reduce(input, KEY, "rid-2", RCV, EGRESS);
        Set<String> oneHashes = one.stream().map(InfluenceEntry::h).collect(Collectors.toSet());
        for (InfluenceEntry e : two) {
            assertFalse(oneHashes.contains(e.h()), e.h());
        }
        assertEquals(one, BoundaryInfluence.reduce(input, KEY, "rid-1", RCV, EGRESS), "derived, so repeatable");
        assertNotEquals(one, BoundaryInfluence.reduce(input, KEY, "rid-1", "other", EGRESS), "bound to the partner");
    }

    @Test
    void genuineOpeningOpens() throws Exception {
        List<InfluenceEntry> reduced = reduce(List.of(ALICE_ORDER, ALICE_CARD, TICKET));
        InfluenceEntry sent = sentFor(reduced, InfluenceClass.PRIVATE, "alice");
        BoundaryInfluence.Opening open = opening(InfluenceClass.PRIVATE, "alice", ALICE_CARD, ALICE_ORDER);
        assertTrue(BoundaryInfluence.opens(sent, open));
        // The order and duplicates of the originals do not matter: the commitment is over their normal form.
        assertTrue(BoundaryInfluence.opens(sent,
                opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, ALICE_CARD, ALICE_ORDER)));
        // It survives the JSON round trip, the form a sender keeps or hands over.
        assertTrue(BoundaryInfluence.opens(sent, BoundaryInfluence.Opening.parse(open.toJson())));
        assertTrue(BoundaryInfluence.opens(sentFor(reduced, InfluenceClass.THIRD_PARTY, null),
                opening(InfluenceClass.THIRD_PARTY, null, TICKET)));
    }

    @Test
    void extraOriginalFails() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER)), InfluenceClass.PRIVATE, "alice");
        assertFalse(BoundaryInfluence.opens(sent, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, ALICE_CARD)));
    }

    @Test
    void missingOriginalFails() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER, ALICE_CARD)), InfluenceClass.PRIVATE, "alice");
        assertFalse(BoundaryInfluence.opens(sent, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER)));
    }

    @Test
    void otherClassOrOwnerFails() {
        List<InfluenceEntry> reduced = reduce(List.of(ALICE_ORDER, TICKET));
        InfluenceEntry sent = sentFor(reduced, InfluenceClass.PRIVATE, "alice");
        String aliceSalt = salt(InfluenceClass.PRIVATE, "alice");
        // An original of another owner, or with no owner, or of another class, beside the genuine one.
        assertFalse(BoundaryInfluence.opens(sent, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, BOB_ORDER)));
        assertFalse(BoundaryInfluence.opens(sent, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, LEDGER)));
        assertFalse(BoundaryInfluence.opens(sent, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, TICKET)));
        // The opening names another class or owner than the sent entry, with the genuine salt and originals.
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(InfluenceClass.PUBLIC, "alice", aliceSalt, List.of(ALICE_ORDER))));
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "bob", aliceSalt, List.of(ALICE_ORDER))));
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, null, aliceSalt, List.of(ALICE_ORDER))));
        // The sent entry relabelled to another owner or class does not open with the genuine opening.
        BoundaryInfluence.Opening genuine = opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER);
        assertTrue(BoundaryInfluence.opens(sent, genuine));
        assertFalse(BoundaryInfluence.opens(
                new InfluenceEntry(InfluenceClass.PRIVATE, sent.src(), sent.h(), null, "bob"), genuine));
        assertFalse(BoundaryInfluence.opens(
                new InfluenceEntry(InfluenceClass.PUBLIC, sent.src(), sent.h(), null, "alice"), genuine));
        // Originals relabelled to match the sent entry's class change the committed bytes.
        InfluenceEntry ticketSent = sentFor(reduced, InfluenceClass.THIRD_PARTY, null);
        InfluenceEntry relabelled = new InfluenceEntry(InfluenceClass.THIRD_PARTY, ALICE_ORDER.src(), ALICE_ORDER.h(),
                ALICE_ORDER.cid(), null);
        assertFalse(BoundaryInfluence.opens(ticketSent, opening(InfluenceClass.THIRD_PARTY, null, relabelled)));
        // A sender that committed bob's entry inside alice's group: the commitment matches, the owners don't.
        String mixed = BoundaryInfluence.commitment(Base64Url.decode(aliceSalt), List.of(ALICE_ORDER, BOB_ORDER));
        InfluenceEntry mixedSent = new InfluenceEntry(InfluenceClass.PRIVATE, sent.src(), mixed, null, "alice");
        assertFalse(BoundaryInfluence.opens(mixedSent,
                opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER, BOB_ORDER)));
    }

    @Test
    void wrongSaltFails() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER)), InfluenceClass.PRIVATE, "alice");
        List<String> wrong = List.of(
                Base64Url.encode(BoundaryInfluence.salt(KEY, "rid-2", RCV, InfluenceClass.PRIVATE, "alice")),
                Base64Url.encode(BoundaryInfluence.salt(KEY, RID, "other", InfluenceClass.PRIVATE, "alice")),
                Base64Url.encode(BoundaryInfluence.salt(KEY, RID, RCV, InfluenceClass.PRIVATE, "bob")),
                Base64Url.encode(BoundaryInfluence.salt(
                        Crypto.sha256("another-key".getBytes(StandardCharsets.UTF_8)), RID, RCV,
                        InfluenceClass.PRIVATE, "alice")),
                Base64Url.encode(new byte[16]));
        for (String s : wrong) {
            assertFalse(BoundaryInfluence.opens(sent,
                    new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, List.of(ALICE_ORDER))), s);
        }
    }

    @Test
    void malformedSaltFails() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER)), InfluenceClass.PRIVATE, "alice");
        byte[] good = BoundaryInfluence.salt(KEY, RID, RCV, InfluenceClass.PRIVATE, "alice");
        List<String> bad = new ArrayList<>(List.of(
                Base64Url.encode(Arrays.copyOf(good, 15)),
                Base64Url.encode(Arrays.copyOf(good, 17)),
                Base64Url.encode(new byte[0]),
                "not base64!",
                "A",
                Base64Url.encode(good) + "+"));
        bad.add(null);
        for (String s : bad) {
            assertFalse(BoundaryInfluence.opens(sent,
                    new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, List.of(ALICE_ORDER))), s);
        }
    }

    @Test
    void emptyOriginalsFails() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER)), InfluenceClass.PRIVATE, "alice");
        String s = salt(InfluenceClass.PRIVATE, "alice");
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, List.of())));
        // A commitment made over no originals still opens nothing.
        InfluenceEntry overNothing = new InfluenceEntry(InfluenceClass.PRIVATE, "boundary:" + EGRESS,
                BoundaryInfluence.commitment(Base64Url.decode(s), List.of()), null, "alice");
        assertFalse(BoundaryInfluence.opens(overNothing,
                new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, List.of())));
    }

    @Test
    void opensIsTotal() {
        InfluenceEntry sent = sentFor(reduce(List.of(ALICE_ORDER)), InfluenceClass.PRIVATE, "alice");
        String s = salt(InfluenceClass.PRIVATE, "alice");
        assertFalse(BoundaryInfluence.opens(null, opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER)));
        assertFalse(BoundaryInfluence.opens(sent, null));
        assertFalse(BoundaryInfluence.opens(sent, new BoundaryInfluence.Opening(null, null, null, null)));
        assertFalse(BoundaryInfluence.opens(sent, new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, null)));
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(null, "alice", s, List.of(ALICE_ORDER))));
        assertFalse(BoundaryInfluence.opens(sent,
                new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", s, Arrays.asList(ALICE_ORDER, null))));
    }

    /** The members in JCS order: {@code cls}, {@code originals}, {@code owner}, {@code salt}. */
    private static String openingText(String cls, String originals, String owner, String salt) {
        StringBuilder sb = new StringBuilder("{");
        if (cls != null) {
            sb.append("\"cls\":").append(cls).append(',');
        }
        if (originals != null) {
            sb.append("\"originals\":").append(originals).append(',');
        }
        if (owner != null) {
            sb.append("\"owner\":").append(owner).append(',');
        }
        if (salt != null) {
            sb.append("\"salt\":").append(salt).append(',');
        }
        if (sb.length() > 1) {
            sb.setLength(sb.length() - 1);
        }
        return sb.append('}').toString();
    }

    @Test
    void openingParseRefusesAnObjectThatIsNotAnOpening() {
        String salt = "\"" + salt(InfluenceClass.PRIVATE, "alice") + "\"";
        String originals = "[{\"cls\":\"private\",\"h\":\"x\",\"owner\":\"alice\",\"src\":\"s\"}]";
        String[] bad = {
            "{}",
            openingText("\"nope\"", originals, "\"alice\"", salt),
            openingText(null, originals, "\"alice\"", salt),
            openingText("\"private\"", originals, "\"\"", salt),
            openingText("\"private\"", originals, "5", salt),
            openingText("\"private\"", originals, "\"alice\"", null),
            openingText("\"private\"", originals, "\"alice\"", "7"),
            openingText("\"private\"", originals, "\"alice\"", "\"AAAA\""),
            openingText("\"private\"", originals, "\"alice\"", "\"not base64!\""),
            openingText("\"private\"", null, "\"alice\"", salt),
            openingText("\"private\"", "{}", "\"alice\"", salt),
            openingText("\"private\"", "[{\"cls\":\"private\"}]", "\"alice\"", salt),
            "{\"cls\":\"private\",\"extra\":1,\"originals\":" + originals + ",\"salt\":" + salt + "}",
        };
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> BoundaryInfluence.Opening.parse(b), b);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> BoundaryInfluence.Opening.parse(b.getBytes(StandardCharsets.UTF_8)), b);
            assertFalse(e instanceof MalformedJsonException, b);
        }
        assertThrows(IllegalArgumentException.class, () -> BoundaryInfluence.Opening.parse((String) null));
        assertThrows(IllegalArgumentException.class, () -> BoundaryInfluence.Opening.parse((byte[]) null));
    }

    @Test
    void aValueThatIsNotAnObjectIsMalformedJson() {
        for (String body : List.of("[]", "42", "\"x\"", "true", "null")) {
            assertThrows(MalformedJsonException.class, () -> BoundaryInfluence.Opening.parse(body), body);
            assertThrows(MalformedJsonException.class,
                    () -> BoundaryInfluence.Opening.parse(body.getBytes(StandardCharsets.UTF_8)), body);
        }
    }

    @Test
    void anOpeningInWireMemberOrderIsMalformedJson() {
        String salt = salt(InfluenceClass.PRIVATE, "alice");
        String wireOrder = "{\"cls\":\"private\",\"owner\":\"alice\",\"salt\":\"" + salt
                + "\",\"originals\":[]}";
        assertThrows(MalformedJsonException.class, () -> BoundaryInfluence.Opening.parse(wireOrder));
        assertThrows(MalformedJsonException.class,
                () -> BoundaryInfluence.Opening.parse(wireOrder.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void openingParseRefusesBytesThatDoNotRead() {
        String json = opening(InfluenceClass.PRIVATE, "alice", ALICE_ORDER).toJson();
        byte[][] unreadable = {
            new byte[0],
            (json + "\n").getBytes(StandardCharsets.UTF_8),
            json.replace(",", ", ").getBytes(StandardCharsets.UTF_8),
            ("\uFEFF" + json).getBytes(StandardCharsets.UTF_8),
            json.getBytes(StandardCharsets.UTF_16LE),
            json.replace("alice", "al\u00efce").getBytes(StandardCharsets.ISO_8859_1),
        };
        for (byte[] b : unreadable) {
            assertThrows(MalformedJsonException.class, () -> BoundaryInfluence.Opening.parse(b));
        }
    }

    @Test
    void anOpeningReadsFromItsBytes() {
        BoundaryInfluence.Opening open = opening(InfluenceClass.PRIVATE, "alice", ALICE_CARD, ALICE_ORDER);
        assertEquals(open, BoundaryInfluence.Opening.parse(open.toJson().getBytes(StandardCharsets.UTF_8)));
        assertEquals(open, BoundaryInfluence.Opening.parse(open.toJson()));
    }

    @Test
    void shortKeyRefused() {
        for (byte[] key : new byte[][] {new byte[31], new byte[33], new byte[0], null}) {
            assertThrows(IllegalArgumentException.class,
                    () -> BoundaryInfluence.reduce(List.of(ALICE_ORDER), key, RID, RCV, EGRESS));
            assertThrows(IllegalArgumentException.class,
                    () -> BoundaryInfluence.reduce(List.of(), key, RID, RCV, EGRESS));
            assertThrows(IllegalArgumentException.class,
                    () -> BoundaryInfluence.salt(key, RID, RCV, InfluenceClass.PRIVATE, "alice"));
        }
    }

    @Test
    void saltIsSixteenBytes() {
        Set<String> seen = new HashSet<>();
        for (InfluenceClass cls : InfluenceClass.values()) {
            for (String owner : Arrays.asList("alice", null)) {
                byte[] s = BoundaryInfluence.salt(KEY, RID, RCV, cls, owner);
                assertEquals(16, s.length);
                assertTrue(seen.add(Base64Url.encode(s)), "a salt per (cls, owner)");
            }
        }
    }

    @Test
    void loadsAKeyOfExactlyThirtyTwoBytesFromItsTrimmedText(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boundary.key");
        Files.writeString(file, "  " + Base64Url.encode(KEY) + "\n");
        assertTrue(Arrays.equals(KEY, BoundaryInfluence.loadKey(file, "the boundary key")));
    }

    @Test
    void refusesAKeyOfAnyOtherLengthNamingTheSettingButNotTheContent(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boundary.key");
        Files.writeString(file, Base64Url.encode(new byte[31]));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> BoundaryInfluence.loadKey(file, "paztport.partner.blinding-key-path"));
        assertEquals("paztport.partner.blinding-key-path must hold 32 bytes as base64url: " + file, e.getMessage());
        Files.writeString(file, "not base64url!");
        assertThrows(IllegalStateException.class, () -> BoundaryInfluence.loadKey(file, "key"));
    }
}
