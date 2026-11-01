// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ResponderEventTest {

    private static final List<String> ALLOWED = List.of("CHAIN_MISSING", "BAD_ORIGIN", "BAD_SIGNATURE", "BROKEN_LINK",
            "EXPIRED", "RID_MISMATCH", "BINDING_MISMATCH", "REPLAY", "PATH_NOT_ALLOWED", "SESSION_UNKNOWN",
            "CLIENT_PATH_NOT_ALLOWED", "INFLUENCE_MISMATCH", "PEER_MISMATCH");

    private static ResponderEvent of(String reason, String svc, String inst, boolean audit) {
        return new ResponderEvent(reason, svc, inst, "r", audit, 1L, "e");
    }

    @Test
    void attributableAcceptsEveryCodeThatReportsWhatTheSenderDid() {
        assertEquals(13, ALLOWED.size());
        for (String reason : ALLOWED) {
            assertTrue(of(reason, "search", "search-1", false).attributable(), reason);
        }
    }

    @Test
    void attributableRefusesEveryOtherReason() {
        for (String reason : List.of("OK", "INFLUENCE_DENIED", "UNSAFE_SESSION", "POLICY_EXPIRED", "SCOPE_DENIED",
                "UNCHECKABLE", "TIME_MISMATCH", "OUTSIDE_SESSION", "NOT_A_CODE", "", "path_not_allowed",
                "PATH_NOT_ALLOWED ")) {
            assertFalse(of(reason, "search", "search-1", false).attributable(), "[" + reason + "]");
        }
    }

    @Test
    void attributableRefusesAnAuditEvent() {
        assertFalse(of("PATH_NOT_ALLOWED", "search", "search-1", true).attributable());
    }

    @Test
    void attributableNeedsBothSuspectNames() {
        assertFalse(of("PATH_NOT_ALLOWED", "", "search-1", false).attributable());
        assertFalse(of("PATH_NOT_ALLOWED", "search", "", false).attributable());
    }

    @Test
    void attributableIsFalseForAMissingField() {
        assertFalse(of(null, "search", "search-1", false).attributable());
        assertFalse(of("PATH_NOT_ALLOWED", null, "search-1", false).attributable());
        assertFalse(of("PATH_NOT_ALLOWED", "search", null, false).attributable());
    }

    @Test
    void toJsonIsTheEventsJcsText() {
        ResponderEvent event = new ResponderEvent("PATH_NOT_ALLOWED", "search", "search-1", "rid", false,
                9_007_199_254_740_991L, "e");
        assertEquals("{\"audit\":false,\"eventId\":\"e\",\"reason\":\"PATH_NOT_ALLOWED\",\"rid\":\"rid\","
                + "\"suspectInst\":\"search-1\",\"suspectSvc\":\"search\",\"ts\":9007199254740991}", event.toJson());
    }

    @Test
    void toJsonRefusesATsNoResponderReads() {
        for (long ts : new long[] {-1, 1L << 53, Long.MIN_VALUE}) {
            ResponderEvent event = new ResponderEvent("PATH_NOT_ALLOWED", "search", "search-1", "rid", false, ts, "e");
            assertThrows(IllegalArgumentException.class, event::toJson, Long.toString(ts));
        }
    }
}
