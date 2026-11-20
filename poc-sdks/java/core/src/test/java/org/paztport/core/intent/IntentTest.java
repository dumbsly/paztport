// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.intent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;

class IntentTest {

    private static final List<String> NEEDS = List.of("amount");
    private static final String WITH_AMOUNT = "{\"facts\":{\"amount\":100,\"order\":\"123\"}}";
    private static final String WITHOUT_AMOUNT = "{\"facts\":{\"order\":\"123\"}}";

    private static Stamp stamp(String svc) {
        return new Stamp(svc, "i", "r", 1L, "s", "rcv", "b", "", "", "sig");
    }

    /** A block naming intent with these items; null items is a block that does not name it. */
    private static Block block(List<String> items) {
        return items == null ? Block.EMPTY : Block.of(Map.of(Intent.NAME, items), List.of());
    }

    private static HandOver handOver(boolean verified, List<String> origin, List<String> second) {
        List<Stamp> stamps = new ArrayList<>(List.of(stamp("origin")));
        List<Block> blocks = new ArrayList<>(List.of(block(origin)));
        if (second != null) {
            stamps.add(stamp("second"));
            blocks.add(block(second));
        }
        return new HandOver(verified, stamps, blocks, ExtensionSettings.of(Set.of(Intent.NAME), null));
    }

    private static ReasonCode readReason(HandOver h) {
        return Intent.readRequest(h.under(Intent.NAME)).reason();
    }

    @Test
    void originHoldsTheItemWithTheFact() {
        HandOver h = handOver(true, List.of(WITH_AMOUNT), null);
        RequestIntent read = Intent.readRequest(h.under(Intent.NAME));
        assertTrue(read.reads());
        assertEquals(100L, read.facts().integer("amount"));
        assertEquals(ReasonCode.OK, Intent.require(h, NEEDS));
    }

    @Test
    void originHoldsTheItemWithoutTheFact() {
        HandOver h = handOver(true, List.of(WITHOUT_AMOUNT), null);
        assertNull(readReason(h));
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(h, NEEDS));
    }

    @Test
    void noStampNamesIntent() {
        HandOver h = handOver(true, null, null);
        RequestIntent read = Intent.readRequest(h.under(Intent.NAME));
        assertTrue(read.reads());
        assertTrue(read.facts().isEmpty());
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(h, NEEDS));
    }

    @Test
    void originNamesItWithNoItems() {
        HandOver h = handOver(true, List.of(), null);
        RequestIntent read = Intent.readRequest(h.under(Intent.NAME));
        assertTrue(read.reads());
        assertTrue(read.facts().isEmpty());
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(h, NEEDS));
    }

    @Test
    void originHoldsTwoItems() {
        HandOver h = handOver(true, List.of(WITH_AMOUNT, WITHOUT_AMOUNT), null);
        assertEquals(ReasonCode.INTENT_MISMATCH, readReason(h));
        assertEquals("origin", Intent.readRequest(h.under(Intent.NAME)).unreadSigner());
        assertEquals(ReasonCode.INTENT_MISMATCH, Intent.require(h, NEEDS));
    }

    @Test
    void originsItemDoesNotRead() {
        HandOver h = handOver(true, List.of("{\"facts\":{}}"), null);
        assertEquals(ReasonCode.INTENT_MISMATCH, readReason(h));
        assertEquals("origin", Intent.readRequest(h.under(Intent.NAME)).unreadSigner());
        assertEquals(ReasonCode.INTENT_MISMATCH, Intent.require(h, NEEDS));
    }

    @Test
    void aLaterStampHoldsAnItem() {
        HandOver h = handOver(true, List.of(WITH_AMOUNT), List.of(WITH_AMOUNT));
        assertEquals(ReasonCode.INTENT_MISMATCH, readReason(h));
        assertEquals("second", Intent.readRequest(h.under(Intent.NAME)).unreadSigner());
        assertEquals(ReasonCode.INTENT_MISMATCH, Intent.require(h, NEEDS));
    }

    @Test
    void aLaterStampNamesItWithNoItems() {
        HandOver h = handOver(true, List.of(WITH_AMOUNT), List.of());
        assertNull(readReason(h));
        assertEquals(ReasonCode.OK, Intent.require(h, NEEDS));
    }

    @Test
    void aHandOverNotVerifiedBelievesNoFact() {
        HandOver h = handOver(false, List.of(WITH_AMOUNT), null);
        assertNull(readReason(h));
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(h, NEEDS));
    }

    @Test
    void noHandOverIsMissing() {
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(null, NEEDS));
    }

    @Test
    void aServiceThatDoesNotActOnIntentHoldsNoFacts() {
        HandOver h = new HandOver(true, List.of(stamp("origin")), List.of(Block.EMPTY),
                ExtensionSettings.of(Set.of("influence"), null));
        RequestIntent read = Intent.readRequest(h.under(Intent.NAME));
        assertTrue(read.reads());
        assertTrue(read.facts().isEmpty());
        assertEquals(ReasonCode.INTENT_MISSING, Intent.require(h, NEEDS));
    }

    @Test
    void withNoNeedsEveryAnswerThatReadsIsOk() {
        assertEquals(ReasonCode.OK, Intent.require(handOver(true, List.of(WITH_AMOUNT), null), List.of()));
        assertEquals(ReasonCode.OK, Intent.require(handOver(true, null, null), List.of()));
        assertEquals(ReasonCode.OK, Intent.require(handOver(false, List.of(WITHOUT_AMOUNT), null), List.of()));
        assertEquals(ReasonCode.OK, Intent.require(null, List.of()));
    }

    @Test
    void anUnreadItemIsMismatchBeforeAMissingName() {
        HandOver h = handOver(true, List.of("{\"facts\":{\"Order\":1}}"), null);
        assertEquals(ReasonCode.INTENT_MISMATCH, Intent.require(h, List.of("amount", "order")));
    }

    @Test
    void nullNeedsIsRefused() {
        assertThrows(NullPointerException.class, () -> Intent.require(handOver(true, List.of(WITH_AMOUNT), null), null));
    }
}
