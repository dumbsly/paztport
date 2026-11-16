// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;

class InfluenceTest {

    @Test
    void anItemThatIsNotAWellFormedEntryIsRefused() {
        String[] bad = {
            "\"x\"",
            "1",
            "[]",
            "null",
            "{\"cls\":\"nope\",\"h\":\"x\",\"src\":\"s\"}",
            "{\"h\":\"x\",\"src\":\"s\"}",
            "{\"cls\":\"public\",\"h\":\"x\",\"src\":1}",
            "{\"cls\":\"public\",\"h\":2,\"src\":\"s\"}",
            "{\"cid\":3,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}",
            "{\"cid\":null,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}",
            "{\"cls\":\"private\",\"h\":\"x\",\"owner\":\"\",\"src\":\"s\"}",
            "{\"cls\":\"private\",\"h\":\"x\",\"owner\":5,\"src\":\"s\"}",
            "{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ud800\"}",
            "{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ufdd0\"}",
            "{\"cls\":\"public\",\"extra\":1,\"h\":\"x\",\"src\":\"s\"}",
            "{\"cls\"",
        };
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> InfluenceEntry.parse(b), b);
        }
    }

    // [] names the extension with nothing to add (influence.md, The every-stamp rule): a hop that acts on influence
    // and read nothing still names it, and the empty block would not.
    @Test
    void aBlockWithNoEntriesNamesInfluence() {
        Block block = Influence.block(List.of(), List.of());
        assertNotEquals(Block.EMPTY, block);
        assertEquals(List.of(), block.itemsUnder(Influence.NAME));
        assertEquals(List.of(), block.requires());
        assertEquals("{\"items\":{\"influence\":[]},\"requires\":[]}", block.toJson());
    }

    @Test
    void aBlockHoldsTheEntriesAsWrittenInTheOrderGiven() {
        InfluenceEntry web = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:example.com", "h2", null, null);
        InfluenceEntry own = new InfluenceEntry(InfluenceClass.PRIVATE, "github:acme/app#42", "h1", "cid-1", "alice");
        Block block = Influence.block(List.of(web, own), List.of(Influence.NAME));
        assertEquals(List.of(web.toJson(), own.toJson()), block.itemsUnder(Influence.NAME));
        assertEquals(List.of(Influence.NAME), block.requires());
        assertEquals(Set.of(Influence.NAME), block.names());
    }

    // A caller that does not act on influence would drop the labels, so a block holding one requires it of the
    // caller (influence.md, Content labels); with no label there is nothing to drop.
    @Test
    void aLabelBlockRequiresInfluenceExactlyWhenItHoldsALabel() {
        ContentLabel label = new ContentLabel(InfluenceClass.PRIVATE, "cid-1", "alice");
        Block labelled = ContentLabel.block(List.of(label), List.of());
        assertEquals(List.of(label.toJson()), labelled.itemsUnder(Influence.NAME));
        assertEquals(List.of(Influence.NAME), labelled.requires());
        assertEquals(List.of(Influence.NAME),
                ContentLabel.block(List.of(label), List.of(Influence.NAME)).requires(), "not added twice");
        assertEquals(List.of("example", Influence.NAME),
                ContentLabel.block(List.of(label), List.of("example")).requires(), "added beside the caller's");
        Block none = ContentLabel.block(List.of(), List.of());
        assertEquals(List.of(), none.itemsUnder(Influence.NAME));
        assertEquals(List.of(), none.requires());
    }

    @Test
    void anItemReadsAsAnEntryOnlyFromItsCanonicalText() {
        InfluenceEntry entry = new InfluenceEntry(InfluenceClass.PRIVATE, "s", "x", "c", "o");
        String text = "{\"cid\":\"c\",\"cls\":\"private\",\"h\":\"x\",\"owner\":\"o\",\"src\":\"s\"}";
        assertEquals(entry, InfluenceEntry.parse(text));
        assertEquals(text, entry.toJson());
        for (String bad : new String[] {"{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\"}",
                " {\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}", "{\"cls\": \"public\",\"h\":\"x\",\"src\":\"s\"}",
                "[{\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]", "{\"cid\":\"c\",\"cls\":\"public\"}"}) {
            assertThrows(IllegalArgumentException.class, () -> InfluenceEntry.parse(bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> InfluenceEntry.parse(null));
    }

    @Test
    void anItemReadsAsALabelOnlyFromItsCanonicalText() {
        ContentLabel label = new ContentLabel(InfluenceClass.PRIVATE, "c", "o");
        String text = "{\"cid\":\"c\",\"cls\":\"private\",\"owner\":\"o\"}";
        assertEquals(label, ContentLabel.parse(text));
        assertEquals(text, label.toJson());
        for (String bad : new String[] {"{\"cls\":\"public\",\"cid\":\"c\"}", " {\"cid\":\"c\",\"cls\":\"public\"}",
                "{\"cid\": \"c\",\"cls\":\"public\"}", "[{\"cid\":\"c\",\"cls\":\"public\"}]",
                "{\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}"}) {
            assertThrows(IllegalArgumentException.class, () -> ContentLabel.parse(bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> ContentLabel.parse(null));
    }

    @Test
    void classWireNames() {
        for (InfluenceClass c : InfluenceClass.values()) {
            assertEquals(c, InfluenceClass.fromWire(c.wire()));
        }
        assertEquals(null, InfluenceClass.fromWire("other"));
    }

    @Test
    void entryRefusesWhatTheBytesCannotCarry() {
        assertThrows(IllegalArgumentException.class, () -> new InfluenceEntry(null, "s", "h", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new InfluenceEntry(InfluenceClass.PUBLIC, null, "h", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new InfluenceEntry(InfluenceClass.PUBLIC, "s", null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new InfluenceEntry(InfluenceClass.PRIVATE, "s", "h", null, ""));
        assertThrows(IllegalArgumentException.class,
                () -> new InfluenceEntry(InfluenceClass.PUBLIC, "\ud800", "h", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new InfluenceEntry(InfluenceClass.PUBLIC, "s", "h", "\udc00", null));
    }

    @Test
    void aLabelHasExactlyTheLabelMembersInJcsOrder() {
        assertEquals(new ContentLabel(InfluenceClass.PUBLIC, "c", null),
                ContentLabel.parse("{\"cid\":\"c\",\"cls\":\"public\"}"));
        for (String bad : new String[] {"{\"cid\":\"c\",\"cls\":\"public\",\"extra\":1}",
                "{\"cls\":\"public\",\"cid\":\"c\"}", "{\"cid\":\"c\"}", "{\"cid\":\"c\",\"cls\":\"bogus\"}",
                " {\"cid\":\"c\",\"cls\":\"public\"}", "{}", "1"}) {
            assertThrows(IllegalArgumentException.class, () -> ContentLabel.parse(bad), bad);
        }
    }

    @Test
    void labelsRoundTripAndRefuseEmptyOwner() {
        ContentLabel fresh = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        assertEquals(fresh, ContentLabel.parse(fresh.toJson()));
        assertEquals(22, ContentLabel.fresh(InfluenceClass.PUBLIC, null).cid().length());
        assertEquals(new InfluenceEntry(InfluenceClass.PRIVATE, "http:x", "h", fresh.cid(), "alice"),
                fresh.toEntry("http:x", "h"));
        String bad = "{\"cid\":\"c\",\"cls\":\"private\",\"owner\":\"\"}";
        assertThrows(IllegalArgumentException.class, () -> ContentLabel.parse(bad));
    }

    /** An OK offline result over one stamp whose block is {@code block}, from a verifier acting on {@code actsOn}. */
    private static OfflineResult okAt(Set<String> actsOn, Block block) {
        Stamp stamp = new Stamp("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "", "", "sig");
        return new OfflineResult(ReasonCode.OK, "", "", new HandOver(true, List.of(stamp), List.of(block),
                ExtensionSettings.of(actsOn, null)));
    }

    private static final Block NOT_AN_ENTRY = Block.of(Map.of(Influence.NAME, List.of("7"),
            "example", List.of("7")), List.of());

    // Such a hand-over holds nothing under influence, so reading it as nothing handed on would pass every item unread:
    // the verifier's configuration is at fault, not the record (spec influence.md, Entries).
    @Test
    void aReadingAtSettingsNotActingOnInfluenceThrows() {
        OfflineResult result = okAt(Set.of("example"), NOT_AN_ENTRY);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> Influence.reason(result));
        assertTrue(e.getMessage().contains("influence") && e.getMessage().contains("settings"), e.getMessage());
    }

    @Test
    void aFailedResultKeepsItsReasonWhateverItsSettings() {
        assertEquals(ReasonCode.REPLAY, Influence.reason(new OfflineResult(ReasonCode.REPLAY, "", "", null)));
    }

    // The control for the two above: the same block at a verifier that acts on influence.
    @Test
    void anActingResultWithAnUnreadableItemIsMismatch() {
        assertEquals(ReasonCode.INFLUENCE_MISMATCH, Influence.reason(okAt(Set.of(Influence.NAME), NOT_AN_ENTRY)));
        assertEquals(ReasonCode.OK, Influence.reason(okAt(Set.of(Influence.NAME), Influence.block(List.of(),
                List.of()))));
    }
}
