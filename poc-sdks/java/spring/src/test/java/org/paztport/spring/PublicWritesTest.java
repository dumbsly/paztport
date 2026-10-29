// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.security.KeyPair;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.RequestBinding;
import org.slf4j.LoggerFactory;

class PublicWritesTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");
    private static final InfluenceEntry RELAYED =
            new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:psp", "h3", null, null);

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

    /** A one-stamp chain from the gateway, as a filter would have verified it. */
    private static List<StampV3> chain(String rid) {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "psp")), 4,
                NOT_AFTER, policy.getPrivate());
        return new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, System::currentTimeMillis)
                .next(null, "psp", RequestBinding.compute("POST", "/charge", new byte[0]), List.of(),
                        built.bundles().get("gateway"))
                .chain();
    }

    /** Asks the trusted-record question in a scope whose chain verified, holding {@code entries}. */
    private boolean trustedWith(InfluenceEntry... entries) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.markVerified(chain("rid-1"));
            PaztportContext.addInfluence(entries);
            return writes.shapedOnlyByTrusted();
        }
    }

    @Test
    void trustedRecordNeedsAScope() {
        assertFalse(writes.shapedOnlyByTrusted());
    }

    // A chain that arrived but did not verify here vouches for nothing, so no influence at all is not enough.
    @Test
    void trustedRecordNeedsAVerifiedChain() {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.setInboundChain(chain("rid-1"));
            assertFalse(writes.shapedOnlyByTrusted());
        }
    }

    @Test
    void trustedRecordRefusesThirdParty() {
        assertFalse(trustedWith(MINE, WEB));
    }

    @Test
    void trustedRecordRefusesLocalUntrusted() {
        assertFalse(trustedWith(RELAYED));
    }

    @Test
    void trustedRecordAllowsVerifiedAndClean() {
        assertTrue(trustedWith());
        assertTrue(trustedWith(MINE));
    }

    @Test
    void trustedRecordTraceLine() {
        trustedWith();
        trustedWith(MINE, WEB);
        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(List.of(
                "PAZTPORT_TRACE decision rid=rid-1 receiver=mailer rule=trusted-record reason=OK ✓ classes=-",
                "PAZTPORT_TRACE decision rid=rid-1 receiver=mailer rule=trusted-record reason=INFLUENCE_DENIED ✗ "
                        + "classes=private,third-party"), lines);
    }
}
