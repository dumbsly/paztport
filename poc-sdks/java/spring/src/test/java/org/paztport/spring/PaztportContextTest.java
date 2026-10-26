// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.PathChain;

class PaztportContextTest {

    @Test
    void storesAndClearsTheInboundChainForThisThread() {
        PathChain chain = new PathChain(List.of());
        PaztportContext.setInboundChain(chain);
        assertSame(chain, PaztportContext.inboundChain());

        PaztportContext.clear();
        assertNull(PaztportContext.inboundChain());
    }

    @Test
    void isIsolatedPerThread() throws Exception {
        PaztportContext.setInboundChain(new PathChain(List.of()));
        PathChain[] seenByOther = new PathChain[1];

        Thread other = new Thread(() -> seenByOther[0] = PaztportContext.inboundChain());
        other.start();
        other.join();

        assertNull(seenByOther[0], "another thread must not see this thread's chain");
        PaztportContext.clear();
    }
}
