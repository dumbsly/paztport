// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.verify.HandOver.StampItems;
import org.paztport.core.verify.ReasonCode;

/** What a service that acts on influence reads from the items handed on, and what it decides from them. */
class RequestInfluenceTest {

    private static final InfluenceEntry OWN = new InfluenceEntry(InfluenceClass.PRIVATE, "github:acme/app#42", "h1",
            "cid-1", "alice");
    private static final InfluenceEntry BOBS = new InfluenceEntry(InfluenceClass.PRIVATE, "github:acme/app#7", "h3",
            null, "bob");
    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:example.com", "h2",
            null, null);
    private static final InfluenceEntry DOCS = new InfluenceEntry(InfluenceClass.PUBLIC, "web:docs.example.org", "h4",
            null, null);
    /** A label: it reads on a response's block, never as an entry on a request's. */
    private static final String LABEL = "{\"cid\":\"cid-1\",\"cls\":\"private\",\"owner\":\"alice\"}";

    private static StampItems stamp(String svc, InfluenceEntry... entries) {
        return new StampItems(svc, Arrays.stream(entries).map(InfluenceEntry::toJson).toList());
    }

    private static StampItems silent(String svc) {
        return new StampItems(svc, null);
    }

    @Test
    void everyItemOfEveryBlockIsReadInChainOrder() {
        RequestInfluence read = Influence.readRequest(List.of(stamp("session"), stamp("pi", OWN, WEB),
                stamp("orders", DOCS, BOBS)));
        assertTrue(read.reads());
        assertTrue(read.everyStampNames());
        assertNull(read.unreadSigner());
        assertEquals(List.of(OWN, WEB, DOCS, BOBS), read.entries());
    }

    // Separates the rule from a check of the caller's block alone: the caller's block names influence and every
    // entry in it is trusted, but the origin's does not name it.
    @Test
    void aBlockThatDoesNotNameInfluenceMeansNotEveryStampNames() {
        RequestInfluence read = Influence.readRequest(List.of(silent("session"), stamp("pi", OWN, DOCS)));
        assertTrue(read.reads());
        assertFalse(read.everyStampNames());
        assertEquals(List.of(OWN, DOCS), read.entries());
    }

    @Test
    void anItemThatIsNotAnEntryNamesItsBlocksSigner() {
        RequestInfluence read = Influence.readRequest(List.of(stamp("session", WEB),
                new StampItems("pi", List.of(WEB.toJson(), LABEL)), new StampItems("orders", List.of(LABEL))));
        assertFalse(read.reads());
        assertEquals("pi", read.unreadSigner());
    }

    @Test
    void nothingHandedOnHoldsNoEntriesAndRefusesNothing() {
        for (List<StampItems> nothing : Arrays.asList(null, List.<StampItems>of())) {
            RequestInfluence read = Influence.readRequest(nothing);
            assertTrue(read.reads(), String.valueOf(nothing));
            assertTrue(read.everyStampNames(), String.valueOf(nothing));
            assertEquals(List.of(), read.entries(), String.valueOf(nothing));
            assertEquals(new Influence.Decision(ReasonCode.OK, true, null),
                    Influence.decide(nothing, List.of(), true, "alice"), String.valueOf(nothing));
        }
    }

    @Test
    void aGuardedWriteAfterABlockThatDoesNotNameInfluenceIsDeniedWhateverTheEntries() {
        List<StampItems> stamps = List.of(silent("session"), stamp("pi", OWN));
        assertEquals(new Influence.Decision(ReasonCode.INFLUENCE_DENIED, false, null),
                Influence.decide(stamps, List.of(), true, "alice"));
        assertEquals(new Influence.Decision(ReasonCode.OK, false, null),
                Influence.decide(stamps, List.of(), false, "alice"), "a read is not decided by the rules");
    }

    @Test
    void untrustedContentWithSomeoneElsesPrivateDataIsDenied() {
        List<StampItems> stamps = List.of(stamp("session"), stamp("pi", WEB, BOBS));
        assertEquals(new Influence.Decision(ReasonCode.INFLUENCE_DENIED, true, null),
                Influence.decide(stamps, List.of(), true, "alice"));
        assertEquals(new Influence.Decision(ReasonCode.OK, true, null),
                Influence.decide(List.of(stamp("session"), stamp("pi", WEB, OWN)), List.of(), true, "alice"),
                "the destination owner's own data");
    }

    // The service's own reads count beside what it was handed: the received private entry is someone else's, but
    // only the untrusted fact the service added makes the write refused.
    @Test
    void whatTheServiceAddedCountsBesideWhatItWasHanded() {
        List<StampItems> stamps = List.of(stamp("session"), stamp("pi", BOBS));
        assertEquals(new Influence.Decision(ReasonCode.OK, true, null),
                Influence.decide(stamps, List.of(), true, "alice"));
        assertEquals(new Influence.Decision(ReasonCode.INFLUENCE_DENIED, true, null),
                Influence.decide(stamps, List.of(new InfluenceFact(InfluenceClass.THIRD_PARTY, null)), true,
                        "alice"));
    }

    // INFLUENCE_MISMATCH comes before either rule: the block that does not name influence would deny the write, and
    // nothing here is untrusted, so neither rule gives it.
    @Test
    void anItemThatDoesNotReadIsAMismatchForAWriteAndARead() {
        List<StampItems> stamps = List.of(silent("session"), new StampItems("pi", List.of(LABEL)));
        for (boolean write : new boolean[] {true, false}) {
            assertEquals(new Influence.Decision(ReasonCode.INFLUENCE_MISMATCH, null, "pi"),
                    Influence.decide(stamps, List.of(), write, "alice"), write ? "a write" : "a read");
        }
    }
}
