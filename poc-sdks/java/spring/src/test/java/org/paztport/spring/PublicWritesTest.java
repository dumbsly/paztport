// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.ReasonCode;
import org.slf4j.LoggerFactory;

class PublicWritesTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final PublicWrites writes = new PublicWrites("mailer");
    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

    @BeforeEach
    void capture() {
        traces.start();
        traceLog.addAppender(traces);
        traceLog.setLevel(Level.INFO);
        traceLog.setAdditive(false);
    }

    @AfterEach
    void cleanup() {
        traceLog.detachAppender(traces);
        traceLog.setLevel(null);
        traceLog.setAdditive(true);
        PaztportContext.reset();
    }

    private ReasonCode decideWith(String owner, InfluenceEntry... entries) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(entries);
            return writes.decide(owner);
        }
    }

    @Test
    void ownDataToOwnerAllowed() {
        assertEquals(ReasonCode.OK, decideWith("alice", WEB, MINE));
    }

    @Test
    void othersDataRefused() {
        assertEquals(ReasonCode.INFLUENCE_DENIED, decideWith("mallory", WEB, MINE));
    }

    @Test
    void unknownOwnerRefused() {
        assertEquals(ReasonCode.INFLUENCE_DENIED, decideWith(null, WEB, MINE));
        assertEquals(ReasonCode.INFLUENCE_DENIED, decideWith("", WEB, MINE));
    }

    @Test
    void noUntrustedAllowed() {
        assertEquals(ReasonCode.OK, decideWith(null, MINE));
    }

    @Test
    void outsideScopeRefused() {
        assertEquals(ReasonCode.INFLUENCE_DENIED, writes.decide("alice"));
    }

    @Test
    void traceLine() {
        decideWith("mallory", WEB, MINE);
        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(1, lines.size());
        assertEquals("PAZTPORT_TRACE decision rid=- receiver=mailer rule=public-write reason=INFLUENCE_DENIED ✗ "
                + "classes=private,third-party", lines.get(0));
        assertFalse(lines.get(0).contains("alice") || lines.get(0).contains("mallory"));
    }
}
