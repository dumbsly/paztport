// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;

class PaztportContextTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final List<StampV3> chain = List.of(StampV3.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
            "", Crypto.generateEd25519KeyPair().getPrivate()));

    @AfterEach
    void cleanup() {
        PaztportContext.reset();
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

    @Test
    void aScopeStartsCleanAndClosingItClearsEverything() {
        PaztportContext.addInfluence(WEB); // left behind by unscoped code on this thread
        assertFalse(PaztportContext.isOpen());

        try (PaztportContext.Scope scope = PaztportContext.open()) {
            assertTrue(PaztportContext.isOpen());
            assertEquals(List.of(), PaztportContext.influence(), "a scope never inherits what came before it");
            PaztportContext.setInboundChain(chain);
            PaztportContext.addInfluence(MINE);
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
        }

        assertFalse(PaztportContext.isOpen());
        assertNull(PaztportContext.inboundChain());
        assertTrue(PaztportContext.influence().isEmpty());
        assertTrue(PaztportContext.labels().isEmpty());
    }

    @Test
    void scopesDoNotNest() {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            assertThrows(IllegalStateException.class, PaztportContext::open);
            assertTrue(PaztportContext.isOpen(), "the refused open leaves the outer scope as it was");
        }
        assertFalse(PaztportContext.isOpen());
    }

    @Test
    void clearEmptiesAnOpenScopeButLeavesItOpen() {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(WEB);
            PaztportContext.clear();
            assertTrue(PaztportContext.influence().isEmpty());
            assertTrue(PaztportContext.isOpen());
        }
    }

    @Test
    void closingAStaleOrDuplicateScopeLeavesTheCurrentOneOpen() {
        PaztportContext.Scope stale = PaztportContext.open();
        stale.close();

        try (PaztportContext.Scope current = PaztportContext.open()) {
            PaztportContext.addInfluence(WEB);
            stale.close();
            stale.close();
            assertTrue(PaztportContext.isOpen(), "a scope that has ended cannot end another");
            assertEquals(List.of(WEB), PaztportContext.influence());
        }
        assertFalse(PaztportContext.isOpen());
    }

    @Test
    void resetEndsALeakedScopeSoANewOneCanOpen() {
        PaztportContext.Scope leaked = PaztportContext.open(); // never closed by the code that opened it
        PaztportContext.addInfluence(WEB);

        PaztportContext.reset();

        assertFalse(PaztportContext.isOpen());
        assertTrue(PaztportContext.influence().isEmpty());
        try (PaztportContext.Scope current = PaztportContext.open()) {
            leaked.close();
            assertTrue(PaztportContext.isOpen(), "the leaked scope, closed late, does not end the new one");
        }
    }

    /**
     * Only the filters beside this class may mark a chain verified, since the boundary signer and the public-writes
     * rule trust the chain marked, and only they may end a scope that other code opened; neither may widen.
     */
    @Test
    void markVerifiedAndResetAreNotPublic() throws Exception {
        for (Method m : List.of(PaztportContext.class.getDeclaredMethod("markVerified", List.class),
                PaztportContext.class.getDeclaredMethod("reset"))) {
            assertFalse(Modifier.isPublic(m.getModifiers()), m.getName() + " must not be public");
            assertFalse(Modifier.isProtected(m.getModifiers()), m.getName() + " must not be protected");
        }
    }
}
