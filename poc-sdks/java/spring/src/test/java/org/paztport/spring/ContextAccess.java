// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import org.paztport.core.stamp.StampV3;

/**
 * Test access to what only the filters may do with the context: mark a chain verified at this hop, and end a scope
 * left open. Tests of the starter's other packages need both, the first to stand in for a chain that verified
 * without running a filter, the second to leave no scope behind on a pooled thread; the methods stay package-private
 * in {@link PaztportContext}, so this lives in its package for that reason only.
 */
public final class ContextAccess {

    private ContextAccess() {
    }

    /** As the filters do once a chain has verified at this hop; only inside an open scope. */
    public static void markVerified(List<StampV3> chain) {
        PaztportContext.markVerified(chain);
    }

    /** As the inbound filter does when a scope other code opened was never closed. */
    public static void reset() {
        PaztportContext.reset();
    }
}
