// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

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

    // Whose private data it is does not matter here: no untrusted content steered the request.
    @Test
    void privateAndPublicContentAloneIsTrusted() {
        assertTrue(InfluenceRule.shapedOnlyByTrusted(List.of()));
        assertTrue(InfluenceRule.shapedOnlyByTrusted(List.of(fact(InfluenceClass.PRIVATE),
                fact(InfluenceClass.PUBLIC))));
    }
}
