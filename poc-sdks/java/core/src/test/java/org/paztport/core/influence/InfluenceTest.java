// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.stamp.Block;

class InfluenceTest {

    @Test
    void rejectsMalformed() {
        String[] bad = {
            "{}",
            "\"x\"",
            "[1]",
            "[[]]",
            "[{\"cls\":\"nope\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":1}]",
            "[{\"cls\":\"public\",\"h\":2,\"src\":\"s\"}]",
            "[{\"cid\":3,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cid\":null,\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]",
            "[{\"cls\":\"private\",\"h\":\"x\",\"owner\":\"\",\"src\":\"s\"}]",
            "[{\"cls\":\"private\",\"h\":\"x\",\"owner\":5,\"src\":\"s\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ud800\"}]",
            "[{\"cls\":\"public\",\"h\":\"x\",\"src\":\"\ufdd0\"}]",
        };
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> Influence.parse(b), b);
        }
        assertThrows(IllegalArgumentException.class, () -> Influence.parse(null));
        assertThrows(IllegalArgumentException.class, () -> Influence.parse("[{\"cls\""));
        String good = "[{\"cid\":\"c\",\"cls\":\"private\",\"h\":\"x\",\"owner\":\"o\",\"src\":\"s\"}]";
        assertEquals(good, Influence.toJson(Influence.parse(good)));
    }

    @Test
    void anEntryWithAnExtraMemberIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[{\"cls\":\"public\",\"extra\":1,\"h\":\"x\",\"src\":\"s\"}]"));
    }

    @Test
    void aListInWireMemberOrderIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[{\"cls\":\"public\",\"src\":\"s\",\"h\":\"x\"}]"));
        assertThrows(IllegalArgumentException.class,
                () -> Influence.parse("[ {\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}]"));
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
    void aLabelListHasExactlyTheLabelMembersInJcsOrder() {
        assertEquals(1, ContentLabel.parseAll("[{\"cid\":\"c\",\"cls\":\"public\"}]").size());
        for (String bad : new String[] {"[{\"cid\":\"c\",\"cls\":\"public\",\"extra\":1}]",
                "[{\"cls\":\"public\",\"cid\":\"c\"}]", "[{\"cid\":\"c\"}]", "[{\"cid\":\"c\",\"cls\":\"bogus\"}]",
                "[ {\"cid\":\"c\",\"cls\":\"public\"}]", "{}", "[1]"}) {
            assertThrows(IllegalArgumentException.class, () -> ContentLabel.parseAll(bad), bad);
        }
    }

    @Test
    void labelsRoundTripAndRefuseEmptyOwner() {
        ContentLabel fresh = ContentLabel.fresh(InfluenceClass.PRIVATE, "alice");
        assertEquals(List.of(fresh), ContentLabel.parseAll(ContentLabel.toJson(List.of(fresh))));
        assertEquals(22, ContentLabel.fresh(InfluenceClass.PUBLIC, null).cid().length());
        assertEquals(new InfluenceEntry(InfluenceClass.PRIVATE, "http:x", "h", fresh.cid(), "alice"),
                fresh.toEntry("http:x", "h"));
        String bad = "[{\"cid\":\"c\",\"cls\":\"private\",\"owner\":\"\"}]";
        assertThrows(IllegalArgumentException.class, () -> ContentLabel.parseAll(bad));
    }
}
