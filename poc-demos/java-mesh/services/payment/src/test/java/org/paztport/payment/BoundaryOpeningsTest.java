// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;

// The listener side of the openings: what each attested call to a partner stood for, kept per rid and partner.
class BoundaryOpeningsTest {

    private static final List<InfluenceEntry> TO_PSP = List.of(
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", null, "alice"));
    private static final List<InfluenceEntry> TO_OTHER = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", null, null));

    @Test
    void keepsTheOriginalsPerRidAndPartner() {
        BoundaryOpenings openings = new BoundaryOpenings();
        openings.sent("rid-1", "psp", TO_PSP, List.of());
        openings.sent("rid-1", "other", TO_OTHER, List.of());

        assertEquals(TO_PSP, openings.originals("rid-1", "psp").orElseThrow());
        assertEquals(TO_OTHER, openings.originals("rid-1", "other").orElseThrow());
        assertTrue(openings.originals("rid-2", "psp").isEmpty());
        assertTrue(openings.originals("rid-1", "nobody").isEmpty());
    }

    @Test
    void forgetsTheOldestPastItsCapacity() {
        BoundaryOpenings openings = new BoundaryOpenings(2);
        openings.sent("rid-1", "psp", TO_PSP, List.of());
        openings.sent("rid-2", "psp", TO_PSP, List.of());
        openings.sent("rid-3", "psp", TO_PSP, List.of());

        assertTrue(openings.originals("rid-1", "psp").isEmpty());
        assertTrue(openings.originals("rid-2", "psp").isPresent());
        assertTrue(openings.originals("rid-3", "psp").isPresent());
    }
}
