// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AttestationEventTest {

    @Test
    void sentAtGivesTheResponderEventWithTheTimeAndIdAdded() {
        ResponderEvent sent = new AttestationEvent("PEER_MISMATCH", "gateway", "10.0.0.7", "rid-1", false)
                .sentAt(1234L, "id-1");
        assertEquals(new ResponderEvent("PEER_MISMATCH", "gateway", "10.0.0.7", "rid-1", false, 1234L, "id-1"), sent);
        assertEquals("{\"reason\":\"PEER_MISMATCH\",\"suspectSvc\":\"gateway\",\"suspectInst\":\"10.0.0.7\","
                + "\"rid\":\"rid-1\",\"audit\":false,\"ts\":1234,\"eventId\":\"id-1\"}", sent.toJson());
    }
}
