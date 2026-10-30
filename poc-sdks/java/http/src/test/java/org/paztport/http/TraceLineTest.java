// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;
import org.slf4j.LoggerFactory;

/**
 * The trace lines operators and the demo read, pinned as literals: one request line, one boundary line and one
 * decision line. They are the lines' format, so moving the code that builds them must leave them byte for byte as
 * they are here.
 */
class TraceLineTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

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
        RequestContext.reset();
    }

    @Test
    void requestLine() {
        VerifyResult refused = new VerifyResult(ReasonCode.PEER_MISMATCH, "gateway", "gw-1");
        assertEquals("PAZTPORT_TRACE request rid=rid-7 reason=PEER_MISMATCH receiver=payment ✗ "
                + "peer=gateway (mTLS) classes=private,third-party",
                HttpReceiver.traceLine("rid-7", refused, "payment", new Peer("gateway", "10.0.0.7"),
                        List.of(MINE, WEB)));
    }

    @Test
    void boundaryLine() {
        assertEquals("PAZTPORT_TRACE boundary rid=rid-7 receiver=bank session=attested status=200 "
                + "classes=private,third-party",
                BoundaryClient.boundaryLine("rid-7", "bank", true, 200, List.of(MINE, WEB)));
    }

    @Test
    void decisionLine() {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.markVerified(chain("rid-7"));
            RequestContext.addInfluence(MINE, WEB);
            new PublicWrites("mailer").decide("mallory");
        }
        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(List.of("PAZTPORT_TRACE decision rid=rid-7 receiver=mailer rule=public-write "
                + "reason=INFLUENCE_DENIED ✗ classes=private,third-party"), lines);
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
}
