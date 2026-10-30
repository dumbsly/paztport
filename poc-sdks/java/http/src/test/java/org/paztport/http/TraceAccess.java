// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.InfluenceEntry;

/**
 * Test access to the egress's trace line, which {@link BoundaryClient} keeps package-private, so this lives in its
 * package for that reason only.
 */
public final class TraceAccess {

    private TraceAccess() {
    }

    /** The {@code PAZTPORT_TRACE boundary} line for one call. */
    public static String boundaryLine(String rid, String receiver, boolean attested, int status,
            List<InfluenceEntry> sent) {
        return BoundaryClient.boundaryLine(rid, receiver, attested, status, sent);
    }
}
