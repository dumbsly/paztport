// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import org.paztport.core.stamp.StampV3;

/**
 * Test access to what only the partner filter may do: mark a chain as verified at this hop. The PSP's handlers
 * read the rid from the verified chain, and running the whole filter (a session, a handshake, a stamped call) to
 * get one would bury what the handler tests are about. Lives in the SDK's package for that reason only.
 */
public final class VerifiedChains {

    private VerifiedChains() {
    }

    /** As the partner filter does after the call verified; only inside an open scope. */
    public static void mark(List<StampV3> chain) {
        PaztportContext.markVerified(chain);
    }
}
