// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class InfluenceRuleTest {

    private static InfluenceFact fact(InfluenceClass cls) {
        return new InfluenceFact(cls, null);
    }

    @Test
    void thirdPartyOrLocalUntrustedContentIsUntrusted() {
        assertFalse(InfluenceRule.shapedOnlyByTrusted(List.of(fact(InfluenceClass.PRIVATE),
                fact(InfluenceClass.THIRD_PARTY))));
        assertFalse(InfluenceRule.shapedOnlyByTrusted(List.of(fact(InfluenceClass.LOCAL_UNTRUSTED))));
    }

    // A stamp that does not name influence is a hop that may have read anything, so no entry can make the write safe:
    // here nothing is untrusted and the only private data is the destination owner's.
    @Test
    void aStampThatDoesNotNameInfluenceRefusesTheWriteWhateverTheEntries() {
        assertTrue(InfluenceRule.guardedWriteRefused(false, List.of(), "bob"));
        assertTrue(InfluenceRule.guardedWriteRefused(false, List.of(new InfluenceFact(InfluenceClass.PRIVATE, "bob"),
                fact(InfluenceClass.PUBLIC)), "bob"));
    }

    @Test
    void whenEveryStampNamesInfluenceTheOwnerAwareRuleDecides() {
        List<List<InfluenceFact>> cases = List.of(List.of(),
                List.of(fact(InfluenceClass.THIRD_PARTY), new InfluenceFact(InfluenceClass.PRIVATE, "bob")),
                List.of(fact(InfluenceClass.THIRD_PARTY), new InfluenceFact(InfluenceClass.PRIVATE, "alice")),
                List.of(fact(InfluenceClass.LOCAL_UNTRUSTED), fact(InfluenceClass.PRIVATE)));
        int refused = 0;
        for (List<InfluenceFact> facts : cases) {
            boolean got = InfluenceRule.guardedWriteRefused(true, facts, "bob");
            assertEquals(InfluenceRule.publicWriteRefused(facts, "bob"), got, facts.toString());
            refused += got ? 1 : 0;
        }
        assertEquals(2, refused, "the cases hold both answers");
    }

    // Whose private data it is does not matter here: no untrusted content steered the request.
    @Test
    void privateAndPublicContentAloneIsTrusted() {
        assertTrue(InfluenceRule.shapedOnlyByTrusted(List.of()));
        assertTrue(InfluenceRule.shapedOnlyByTrusted(List.of(fact(InfluenceClass.PRIVATE),
                fact(InfluenceClass.PUBLIC))));
    }
}
