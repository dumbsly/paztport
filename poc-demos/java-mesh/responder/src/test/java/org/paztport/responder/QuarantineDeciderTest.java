// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.paztport.core.ResponderEvent;

class QuarantineDeciderTest {

    private final long[] now = {0L};

    private QuarantineDecider decider() {
        // threshold 3 in 60s; at most 2 quarantines per service in 600s
        return new QuarantineDecider(new QuarantineConfig(3, 60_000, 2, 600_000), () -> now[0]);
    }

    private static ResponderEvent event(String svc, String inst) {
        return event("PATH_NOT_ALLOWED", svc, inst);
    }

    private static ResponderEvent event(String reason, String svc, String inst) {
        return new ResponderEvent(reason, svc, inst, "rid", false, 0L, "e");
    }

    @Test
    void belowThresholdIsNone() {
        QuarantineDecider d = decider();
        assertEquals(QuarantineDecision.NONE, d.observe(event("search", "s1")));
        assertEquals(QuarantineDecision.NONE, d.observe(event("search", "s1")));
    }

    @Test
    void thirdEventInWindowQuarantines() {
        QuarantineDecider d = decider();
        d.observe(event("search", "s1"));
        d.observe(event("search", "s1"));
        assertEquals(QuarantineDecision.QUARANTINE, d.observe(event("search", "s1")));
    }

    @Test
    void auditEventsAreIgnored() {
        QuarantineDecider d = decider();
        ResponderEvent audit = new ResponderEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", true, 0L, "e");
        assertEquals(QuarantineDecision.NONE, d.observe(audit));
        assertEquals(QuarantineDecision.NONE, d.observe(audit));
        assertEquals(QuarantineDecision.NONE, d.observe(audit));
    }

    @Test
    void policyRefusalsNeverCount() {
        // The chain was sound; payment's policy declined what shaped it. That is not misbehaviour.
        QuarantineDecider d = decider();
        for (int i = 0; i < 3; i++) {
            assertEquals(QuarantineDecision.NONE, d.observe(event("INFLUENCE_DENIED", "search", "s1")));
        }
        for (int i = 0; i < 3; i++) {
            assertEquals(QuarantineDecision.NONE, d.observe(event("UNSAFE_SESSION", "search", "s1")));
        }
    }

    @Test
    void blankInstanceIsNeverActioned() {
        QuarantineDecider d = decider();
        for (int i = 0; i < 5; i++) {
            assertEquals(QuarantineDecision.NONE, d.observe(event("search", "")));
        }
    }

    @Test
    void eventsOutsideTheWindowDoNotCount() {
        QuarantineDecider d = decider();
        d.observe(event("search", "s1"));
        d.observe(event("search", "s1"));
        now[0] = 61_000; // both earlier events now expired
        assertEquals(QuarantineDecision.NONE, d.observe(event("search", "s1")));
    }

    @Test
    void differentInstancesAreCountedSeparately() {
        QuarantineDecider d = decider();
        d.observe(event("search", "s1"));
        d.observe(event("search", "s1"));
        assertEquals(QuarantineDecision.NONE, d.observe(event("search", "s2")));
    }

    @Test
    void oneServicesEventsDoNotCountAgainstAnotherServicesInstance() {
        QuarantineDecider d = decider();
        // search names gateway's container gw1 as its own instance
        d.observe(event("search", "gw1"));
        d.observe(event("search", "gw1"));
        assertEquals(QuarantineDecision.NONE, d.observe(event("gateway", "gw1")));
        assertEquals(QuarantineDecision.QUARANTINE, d.observe(event("search", "gw1")));
    }

    @Test
    void instanceWindowResetsAfterAQuarantine() {
        QuarantineDecider d = decider();
        d.observe(event("search", "s1"));
        d.observe(event("search", "s1"));
        assertEquals(QuarantineDecision.QUARANTINE, d.observe(event("search", "s1")));
        // Needs a fresh three to act again, not just one more.
        assertEquals(QuarantineDecision.NONE, d.observe(event("search", "s1")));
    }

    @Test
    void circuitBreakerEscalatesBeyondMaxPerService() {
        QuarantineDecider d = decider();
        // first quarantine
        d.observe(event("search", "s1"));
        d.observe(event("search", "s1"));
        assertEquals(QuarantineDecision.QUARANTINE, d.observe(event("search", "s1")));
        // second quarantine (replacement instance)
        d.observe(event("search", "s2"));
        d.observe(event("search", "s2"));
        assertEquals(QuarantineDecision.QUARANTINE, d.observe(event("search", "s2")));
        // third threshold within the service window -> circuit breaker trips
        d.observe(event("search", "s3"));
        d.observe(event("search", "s3"));
        assertEquals(QuarantineDecision.ESCALATE, d.observe(event("search", "s3")));
    }
}
