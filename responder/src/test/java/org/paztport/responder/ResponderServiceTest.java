// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResponderServiceTest {

    private final RecordingQuarantiner quarantiner = new RecordingQuarantiner();

    private ResponderService service() {
        QuarantineDecider decider = new QuarantineDecider(new QuarantineConfig(3, 60_000, 2, 600_000), () -> 0L);
        // run the action on the calling thread so assertions are deterministic
        return new ResponderService(decider, quarantiner, Runnable::run);
    }

    private static ResponderEvent illicit(String inst) {
        return new ResponderEvent("PATH_NOT_ALLOWED", "search", inst, "rid", false, 0L, "e");
    }

    @Test
    void reachingThresholdQuarantinesTheInstance() {
        ResponderService service = service();
        service.handle(illicit("s1"));
        service.handle(illicit("s1"));
        assertEquals(QuarantineDecision.QUARANTINE, service.handle(illicit("s1")));

        assertEquals(1, quarantiner.calls.size());
        assertEquals("search", quarantiner.calls.get(0)[0]);
        assertEquals("s1", quarantiner.calls.get(0)[1]);
    }

    @Test
    void escalationDoesNotQuarantine() {
        ResponderService service = service();
        // two quarantines exhaust the per-service budget
        for (String inst : List.of("s1", "s2")) {
            service.handle(illicit(inst));
            service.handle(illicit(inst));
            service.handle(illicit(inst));
        }
        quarantiner.calls.clear();

        service.handle(illicit("s3"));
        service.handle(illicit("s3"));
        assertEquals(QuarantineDecision.ESCALATE, service.handle(illicit("s3")));
        assertTrue(quarantiner.calls.isEmpty(), "escalation must not quarantine");
    }

    @Test
    void auditEventsDoNothing() {
        ResponderService service = service();
        ResponderEvent audit = new ResponderEvent("PATH_NOT_ALLOWED", "search", "s1", "rid", true, 0L, "e");
        assertEquals(QuarantineDecision.NONE, service.handle(audit));
        assertEquals(QuarantineDecision.NONE, service.handle(audit));
        assertEquals(QuarantineDecision.NONE, service.handle(audit));
        assertTrue(quarantiner.calls.isEmpty());
    }

    @Test
    void aForgedNewlineInTheInstanceStaysOnOneLogLine() {
        ResponderService service = service();
        String inst = "s1\nESCALATE svc=search inst=s1";
        service.handle(illicit(inst));
        service.handle(illicit(inst));
        List<String> lines;
        try (LogCapture capture = new LogCapture(ResponderService.class)) {
            assertEquals(QuarantineDecision.QUARANTINE, service.handle(illicit(inst)));
            lines = capture.lines();
        }
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).startsWith("QUARANTINE svc=search"), lines.get(0));
        assertFalse(lines.get(0).contains("\n"), lines.get(0));
        // the action itself still gets the name as signed
        assertEquals(inst, quarantiner.calls.get(0)[1]);
    }

    private static final class RecordingQuarantiner implements Quarantiner {
        final List<String[]> calls = new ArrayList<>();

        @Override
        public void quarantine(String suspectSvc, String suspectInst) {
            calls.add(new String[] {suspectSvc, suspectInst});
        }
    }
}
