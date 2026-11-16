// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;

class ServedUnverifiedTest {

    private static final PrivateKey KEY = Crypto.generateEd25519KeyPair().getPrivate();
    private static final ExtensionSettings EXAMPLE = ExtensionSettings.of(Set.of("example"), Set.of("example"));

    private static final Block NAMED = Block.of(Map.of("example", List.of("{\"note\":\"n1\"}", "7")), List.of());
    private static final Block OTHER = Block.of(Map.of("other", List.of("1"), "example", List.of("2")), List.of());

    private static Stamp stamp(String svc, Block block, String prev) {
        return Stamp.sign(svc, "i", "r", 1L, "s", "next", "b", block.commit(), prev, KEY);
    }

    private static String chain(Block first, Block second) {
        Stamp a = stamp("gateway", first, "");
        return Chains.toJson(List.of(a, stamp("orders", second, a.sig())));
    }

    private static ServedUnverified served(String chain, String blocks) {
        return ServedUnverified.of(chain, blocks, EXAMPLE);
    }

    @Test
    void aChainThatReadsWithMatchingBlocksHandsThemOnAsNotVerified() {
        ServedUnverified s = served(chain(Block.EMPTY, NAMED), Block.toJson(List.of(Block.EMPTY, NAMED)));
        assertTrue(s.blocksMatch());
        assertFalse(s.handOver().verified());
        assertEquals(List.of(new HandOver.StampItems("gateway", null),
                new HandOver.StampItems("orders", List.of("{\"note\":\"n1\"}", "7"))), s.handOver().under("example"));
    }

    @Test
    void noBlocksAndEveryExtEmptyHandsOnEmptyEntries() {
        ServedUnverified s = served(chain(Block.EMPTY, Block.EMPTY), null);
        assertTrue(s.blocksMatch());
        assertEquals(List.of(new HandOver.StampItems("gateway", null), new HandOver.StampItems("orders", null)),
                s.handOver().under("example"));
    }

    @Test
    void noBlocksWhereAStampCommitsToOneDoesNotMatch() {
        ServedUnverified s = served(chain(Block.EMPTY, NAMED), null);
        assertFalse(s.blocksMatch());
        assertNull(s.handOver());
    }

    @Test
    void aBlockAlteredDoesNotMatch() {
        Block altered = Block.of(Map.of("example", List.of("8")), List.of());
        assertFalse(served(chain(Block.EMPTY, NAMED), Block.toJson(List.of(Block.EMPTY, altered))).blocksMatch());
    }

    @Test
    void oneBlockTooFewDoesNotMatch() {
        assertFalse(served(chain(Block.EMPTY, Block.EMPTY), Block.toJson(List.of(Block.EMPTY))).blocksMatch());
    }

    @Test
    void blocksThatAreJsonNullDoNotMatch() {
        assertFalse(served(chain(Block.EMPTY, Block.EMPTY), "null").blocksMatch());
    }

    @Test
    void aChainThatDoesNotReadWithBlocksThatReadIsServedWithNothingHandedOn() {
        ServedUnverified s = served("[]", Block.toJson(List.of(NAMED)));
        assertTrue(s.blocksMatch());
        assertNull(s.handOver());
    }

    @Test
    void aChainThatDoesNotReadWithBlocksThatAreAnObjectDoesNotMatch() {
        ServedUnverified s = served("[]", "{}");
        assertFalse(s.blocksMatch());
        assertNull(s.handOver());
    }

    @Test
    void noChainAndNoBlocksIsServedWithNothingHandedOn() {
        ServedUnverified s = served(null, null);
        assertTrue(s.blocksMatch());
        assertNull(s.handOver());
    }

    @Test
    void aBadSignatureDoesNotMatter() {
        Stamp good = stamp("gateway", NAMED, "");
        Stamp bad = new Stamp(good.svc(), good.inst(), good.rid(), good.ts(), good.sess(), good.rcv(), good.bind(),
                good.ext(), good.prev(), good.sig().equals("AAAA") ? "BBBB" : "AAAA");
        ServedUnverified s = served(Chains.toJson(List.of(bad)), Block.toJson(List.of(NAMED)));
        assertTrue(s.blocksMatch());
        assertEquals(List.of(new HandOver.StampItems("gateway", List.of("{\"note\":\"n1\"}", "7"))),
                s.handOver().under("example"));
    }

    @Test
    void aNameOutsideTheAllowedListIsNeverHandedOn() {
        ServedUnverified s = served(chain(Block.EMPTY, OTHER), Block.toJson(List.of(Block.EMPTY, OTHER)));
        assertTrue(s.blocksMatch());
        assertEquals(Set.of("example"), s.handOver().names());
        assertNull(s.handOver().under("other"));
    }

    @Test
    void aLastBlockRequiringAnExtensionNotActedOnStillMatches() {
        Block requiring = Block.of(Map.of(), List.of("influence"));
        ServedUnverified s = served(chain(Block.EMPTY, requiring), Block.toJson(List.of(Block.EMPTY, requiring)));
        assertTrue(s.blocksMatch());
        assertFalse(s.handOver().verified());
    }
}
