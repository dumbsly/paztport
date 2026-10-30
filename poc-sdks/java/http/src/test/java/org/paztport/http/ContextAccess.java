// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.stamp.StampV3;

/**
 * Test access to what only {@link RequestContext#accept} may do with the context: mark a chain verified at this hop,
 * and end a scope left open. Tests in other packages need both, the first to stand in for a chain that verified
 * without running a receiver, the second to leave no scope behind on a pooled thread; the methods stay
 * package-private in {@link RequestContext}, so this lives in its package for that reason only.
 */
public final class ContextAccess {

    private ContextAccess() {
    }

    /** As the binding does once a chain has verified at this hop; only inside an open scope. */
    public static void markVerified(List<StampV3> chain) {
        RequestContext.markVerified(chain);
    }

    /** As the binding does when a scope other code opened was never closed. */
    public static void reset() {
        RequestContext.reset();
    }
}
