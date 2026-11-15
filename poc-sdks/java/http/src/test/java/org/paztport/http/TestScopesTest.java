// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;

class TestScopesTest {

    private final List<Stamp> chain = List.of(Stamp.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
            "", Crypto.generateEd25519KeyPair().getPrivate()));

    @AfterEach
    void cleanup() {
        RequestContext.reset();
    }

    @Test
    void actOnMakesAnOwnerWriteAnswerWhereABareScopeDenies() {
        PublicWrites writes = new PublicWrites("orders");
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertEquals(ReasonCode.INFLUENCE_DENIED, writes.decide("alice"), "a bare scope has no settings");
            TestScopes.actOn(ExtensionSettings.of(Set.of(Influence.NAME), null));
            assertEquals(ReasonCode.OK, writes.decide("alice"));
        }
    }

    @Test
    void verifiedSetsTheChainAndWhatWasHandedOn() {
        HandOver handOver = new HandOver(true, chain, List.of(Block.EMPTY), ExtensionSettings.NONE);
        try (RequestContext.Scope scope = RequestContext.open()) {
            TestScopes.verified(chain, handOver);
            assertSame(chain, RequestContext.verifiedChain());
            assertSame(handOver, RequestContext.handedOn());
        }
    }

    @Test
    void aHandOverThatIsNotVerifiedIsRefused() {
        HandOver unverified = new HandOver(false, chain, List.of(Block.EMPTY), ExtensionSettings.NONE);
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertThrows(IllegalArgumentException.class, () -> TestScopes.verified(chain, unverified));
            assertNull(RequestContext.verifiedChain(), "nothing was set");
            assertNull(RequestContext.handedOn());
        }
    }
}
