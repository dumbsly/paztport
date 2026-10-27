// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.ContentLabel;
import org.paztport.core.Crypto;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.StampV3;

class PaztportContextTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final List<StampV3> chain = List.of(StampV3.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
            "", Crypto.generateEd25519KeyPair().getPrivate()));

    @AfterEach
    void cleanup() {
        PaztportContext.clear();
    }

    @Test
    void storesAndClearsTheInboundChainForThisThread() {
        PaztportContext.setInboundChain(chain);
        assertSame(chain, PaztportContext.inboundChain());

        PaztportContext.clear();
        assertNull(PaztportContext.inboundChain());
    }

    @Test
    void influenceAccumulatesInOrder() {
        assertTrue(PaztportContext.influence().isEmpty());
        PaztportContext.addInfluence(WEB);
        PaztportContext.addInfluence(MINE, WEB);
        assertEquals(List.of(WEB, MINE, WEB), PaztportContext.influence());
        assertThrows(UnsupportedOperationException.class, () -> PaztportContext.influence().clear());
    }

    @Test
    void labelMintsAFreshContentIdEachTime() {
        PaztportContext.label(InfluenceClass.PRIVATE, "alice");
        PaztportContext.label(InfluenceClass.PUBLIC, null);
        List<ContentLabel> labels = PaztportContext.labels();
        assertEquals(2, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        assertNull(labels.get(1).owner());
        assertTrue(!labels.get(0).cid().equals(labels.get(1).cid()));
    }

    @Test
    void clearResetsEverything() {
        PaztportContext.setInboundChain(chain);
        PaztportContext.addInfluence(WEB);
        PaztportContext.label(InfluenceClass.PUBLIC, null);

        PaztportContext.clear();

        assertNull(PaztportContext.inboundChain());
        assertTrue(PaztportContext.influence().isEmpty());
        assertTrue(PaztportContext.labels().isEmpty());
    }

    @Test
    void isIsolatedPerThread() throws Exception {
        PaztportContext.setInboundChain(chain);
        PaztportContext.addInfluence(WEB);
        Object[] seenByOther = new Object[2];

        Thread other = new Thread(() -> {
            seenByOther[0] = PaztportContext.inboundChain();
            seenByOther[1] = PaztportContext.influence();
        });
        other.start();
        other.join();

        assertNull(seenByOther[0], "another thread must not see this thread's chain");
        assertEquals(List.of(), seenByOther[1], "nor its influence");
    }
}
