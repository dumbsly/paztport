// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class CardRecordsTest {

    @Test
    void attestedChargeRegistersOwner() {
        CardRecords records = new CardRecords();
        records.charge("alice", "123", "4242 4242 4242 4242", true);

        assertEquals("alice", records.ownerOf("4242424242424242"));
        assertEquals("4242424242424242", records.cardFor("123"));
    }

    // A charge in an unsafe session came from a caller nobody vouched for, so it must never make a card someone's.
    @Test
    void unsafeChargeRegistersNothing() {
        CardRecords records = new CardRecords();
        records.charge("mallory", "456", "4000 0000 0000 0002", false);

        assertNull(records.ownerOf("4000000000000002"));
        assertNull(records.cardFor("456"));
    }

    @Test
    void firstOwnerWins() {
        CardRecords records = new CardRecords();
        records.charge("alice", "123", "4242424242424242", true);
        records.charge("mallory", "456", "4242-4242-4242-4242", true);

        assertEquals("alice", records.ownerOf("4242424242424242"));
        assertEquals("4242424242424242", records.cardFor("456"));
    }

    @Test
    void normalisesDigits() {
        assertEquals("4242424242424242", CardRecords.normalise("4242 4242-4242 4242"));
    }

    @Test
    void unknownIsNull() {
        CardRecords records = new CardRecords();
        assertNull(records.ownerOf("4242424242424242"));
        assertNull(records.cardFor("123"));
        assertNull(records.ownerOf(null));
        assertNull(records.cardFor(null));
    }

    // The card that paid for an order is the payer's: a later charge for the same order must not re-point it.
    @Test
    void firstCardForAnOrderWins() {
        CardRecords records = new CardRecords();
        records.charge("alice", "123", "4242424242424242", true);
        records.charge("alice", "123", "5555 5555 5555 4444", true);

        assertEquals("4242424242424242", records.cardFor("123"));
    }
}
