// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;

/**
 * The boundary trace line the egress logs for each call, pinned as a literal: it is the line operators and the demo
 * read, so moving the code that builds it must leave it byte for byte as it is here.
 */
class BoundaryLineTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    @Test
    void boundaryLine() {
        assertEquals("PAZTPORT_TRACE boundary rid=rid-7 receiver=bank session=attested status=200 "
                + "classes=private,third-party",
                BoundaryClient.boundaryLine("rid-7", "bank", true, 200, List.of(MINE, WEB)));
    }
}
