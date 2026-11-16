// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.paztport.core.influence.InfluenceClass.LOCAL_UNTRUSTED;
import static org.paztport.core.influence.InfluenceClass.PRIVATE;
import static org.paztport.core.influence.InfluenceClass.PUBLIC;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.verify.HandOver.StampItems;
import org.paztport.core.verify.ReasonCode;

/**
 * What a caller that acts on influence adds for one response over HTTP (spec influence.md, Content labels): the
 * response stamp's own entry of the hand-over, never every block of the chain, which is the MCP rule.
 */
class ResponseEntriesTest {

    private static final List<InfluenceEntry> UNTRUSTED =
            List.of(new InfluenceEntry(LOCAL_UNTRUSTED, "http:orders", "rh", null, null));

    @Test
    void aResponseThatVerifiesAddsOneEntryPerLabel() {
        assertEquals(List.of(new InfluenceEntry(PRIVATE, "http:orders", "rh", "cid-1", "alice")),
                Influence.responseEntries(ReasonCode.OK, new StampItems("orders",
                        List.of("{\"cid\":\"cid-1\",\"cls\":\"private\",\"owner\":\"alice\"}")), "http:orders", "rh"));
        assertEquals(List.of(new InfluenceEntry(PUBLIC, "http:orders", "rh", "c1", null),
                new InfluenceEntry(PRIVATE, "http:orders", "rh", "c2", "bob")),
                Influence.responseEntries(ReasonCode.OK, new StampItems("orders",
                        List.of("{\"cid\":\"c1\",\"cls\":\"public\"}",
                                "{\"cid\":\"c2\",\"cls\":\"private\",\"owner\":\"bob\"}")),
                        "http:orders", "rh"), "in the order the block holds them");
    }

    @Test
    void aResponseThatNamesInfluenceWithNoLabelAddsNothing() {
        assertEquals(List.of(), Influence.responseEntries(ReasonCode.OK, new StampItems("orders", List.of()),
                "http:orders", "rh"));
    }

    @Test
    void aSilentResponseIsLocalUntrusted() {
        assertEquals(UNTRUSTED, Influence.responseEntries(ReasonCode.OK, new StampItems("orders", null),
                "http:orders", "rh"));
    }

    // The label that reads is not taken either: the response's labels count only when every item is one.
    @Test
    void aResponseWithAnItemThatIsNotALabelIsLocalUntrusted() {
        assertEquals(UNTRUSTED, Influence.responseEntries(ReasonCode.OK, new StampItems("orders",
                List.of("{\"cid\":\"c\",\"cls\":\"public\"}", "{\"cls\":\"public\",\"h\":\"x\",\"src\":\"s\"}")),
                "http:orders", "rh"));
    }

    @Test
    void aResponseThatDidNotVerifyIsLocalUntrusted() {
        assertEquals(UNTRUSTED, Influence.responseEntries(ReasonCode.EXTENSION_REQUIRED,
                new StampItems("orders", List.of()), "http:orders", "rh"));
        assertEquals(UNTRUSTED, Influence.responseEntries(ReasonCode.BAD_SIGNATURE, null, "http:orders", "rh"));
        assertEquals(UNTRUSTED, Influence.responseEntries(null, null, "http:orders", "rh"), "no check ran");
        assertEquals(UNTRUSTED, Influence.responseEntries(ReasonCode.OK, null, "http:orders", "rh"),
                "no entry of the response stamp's own");
    }
}
