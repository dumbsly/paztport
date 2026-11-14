// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;

class HandOverTest {

    private static Stamp stamp(String svc) {
        return new Stamp(svc, "i", "r", 1L, "s", "rcv", "b", "", "", "sig");
    }

    private static HandOver handOver(boolean verified) {
        Block named = Block.of(Map.of("example", List.of("{\"note\":\"n1\"}", "7")), List.of("influence"));
        return new HandOver(verified, List.of(stamp("gateway"), stamp("orders")), List.of(Block.EMPTY, named),
                ExtensionSettings.of(Set.of("example", "influence"), null));
    }

    @Test
    void eachNameHoldsOneEntryPerStampInChainOrder() {
        assertEquals(List.of(new HandOver.StampItems("gateway", null),
                new HandOver.StampItems("orders", List.of("{\"note\":\"n1\"}", "7"))), handOver(true).under("example"));
    }

    @Test
    void aNameOnlyInRequiresIsNotNamed() {
        assertEquals(Arrays.asList(new HandOver.StampItems("gateway", null), new HandOver.StampItems("orders", null)),
                handOver(true).under("influence"));
    }

    @Test
    void aNameTheServiceDoesNotActOnIsNull() {
        assertNull(handOver(true).under("other"));
    }

    @Test
    void namesAndVerifiedAreWhatWasPassed() {
        assertEquals(Set.of("example", "influence"), handOver(true).names());
        assertTrue(handOver(true).verified());
        assertFalse(handOver(false).verified());
    }

    @Test
    void theListsAreUnmodifiable() {
        HandOver h = handOver(true);
        assertThrows(UnsupportedOperationException.class, () -> h.under("example").clear());
        assertThrows(UnsupportedOperationException.class, () -> h.names().add("x"));
    }

    @Test
    void equalityIsByValue() {
        assertEquals(handOver(true), handOver(true));
        assertEquals(handOver(true).hashCode(), handOver(true).hashCode());
        assertFalse(handOver(true).equals(handOver(false)));
    }

    @Test
    void stampsAndBlocksOfDifferentLengthsAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> new HandOver(true, List.of(stamp("a")), List.of(),
                ExtensionSettings.NONE));
    }

    /** The rule both verifiers' results keep: a verified hand-over exactly on OK, nothing on a refusal. */
    @Test
    void aResultHandsOverAVerifiedHandOverExactlyOnOk() {
        HandOver verified = handOver(true);
        HandOver served = handOver(false);
        HandOver.requireFor(ReasonCode.OK, verified);
        HandOver.requireFor(ReasonCode.EXTENSION_MISMATCH, null);
        assertThrows(IllegalArgumentException.class, () -> HandOver.requireFor(ReasonCode.OK, null));
        assertThrows(IllegalArgumentException.class, () -> HandOver.requireFor(ReasonCode.OK, served));
        assertThrows(IllegalArgumentException.class,
                () -> HandOver.requireFor(ReasonCode.EXTENSION_MISMATCH, verified));
        assertThrows(IllegalArgumentException.class, () -> HandOver.requireFor(ReasonCode.PATH_NOT_ALLOWED, served));
        // Both results hold it.
        assertEquals(verified, new VerifyResult(ReasonCode.OK, "pi", "i", verified).handOver());
        assertEquals(verified, new OfflineResult(ReasonCode.OK, "pi", "i", verified).handOver());
        assertThrows(IllegalArgumentException.class, () -> new VerifyResult(ReasonCode.OK, "pi", "i", null));
        assertThrows(IllegalArgumentException.class, () -> new VerifyResult(ReasonCode.OK, "pi", "i", served));
        assertThrows(IllegalArgumentException.class, () -> new VerifyResult(ReasonCode.REPLAY, "", "", verified));
        assertThrows(IllegalArgumentException.class, () -> new OfflineResult(ReasonCode.OK, "pi", "i", null));
        assertThrows(IllegalArgumentException.class, () -> new OfflineResult(ReasonCode.OK, "pi", "i", served));
        assertThrows(IllegalArgumentException.class, () -> new OfflineResult(ReasonCode.REPLAY, "", "", verified));
    }
}
