// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.security.KeyPair;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;

class PublicWritesTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");
    private static final InfluenceEntry UNOWNED = new InfluenceEntry(InfluenceClass.PRIVATE, "db:b", "h4", null, null);
    private static final InfluenceEntry PUBLISHED =
            new InfluenceEntry(InfluenceClass.PUBLIC, "web:docs", "h5", null, null);
    private static final InfluenceEntry RELAYED =
            new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:psp", "h3", null, null);

    private static final ExtensionSettings ACTS = ExtensionSettings.of(Set.of(Influence.NAME), null);

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
        RequestContext.reset();
    }

    private ReasonCode decideWith(String owner, InfluenceEntry... entries) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(ACTS);
            RequestContext.addInfluence(entries);
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

    /** A one-stamp chain from the gateway, as a receiver would have verified it. */
    private static List<Stamp> chain(String rid) {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "psp")), 4,
                NOT_AFTER, policy.getPrivate());
        return new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, System::currentTimeMillis)
                .next(null, "psp", RequestBinding.compute("POST", "/charge", new byte[0]), Block.EMPTY,
                        built.bundles().get("gateway"))
                .chain();
    }

    /** Asks the trusted-record question in a scope whose chain verified, holding {@code entries}. */
    private boolean trustedWith(InfluenceEntry... entries) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(ACTS);
            RequestContext.markVerified(chain("rid-1"));
            RequestContext.addInfluence(entries);
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
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(ACTS);
            RequestContext.setInboundChain(chain("rid-1"));
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

    // Whose private data it is does not matter here: no untrusted content steered the request.
    @Test
    void trustedRecordAllowsVerifiedAndClean() {
        assertTrue(trustedWith());
        assertTrue(trustedWith(MINE));
        assertTrue(trustedWith(UNOWNED));
    }

    /**
     * The every-stamp rule holds for a trusted record too: a hop that does not name influence may have read anything,
     * so a verified chain with such a stamp writes no trusted record, however clean the entries it holds.
     */
    @Test
    void aTrustedRecordNeedsEveryStampToNameInfluence() {
        List<Stamp> chain = chain("rid-1");
        Block named = Influence.block(List.of(MINE), List.of());
        assertFalse(trustedHandedOn(chain, List.of(Block.EMPTY)), "the one stamp does not name influence");
        assertTrue(trustedHandedOn(chain, List.of(named)));
        assertFalse(trustedHandedOn(chain, List.of(Influence.block(List.of(WEB), List.of()))));
    }

    /** Asks the trusted-record question in a scope whose chain verified with {@code blocks} handed on. */
    private boolean trustedHandedOn(List<Stamp> chain, List<Block> blocks) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(ACTS);
            RequestContext.markVerified(chain);
            RequestContext.handOn(new HandOver(true, chain, blocks, ExtensionSettings.of(Set.of(Influence.NAME),
                    null)));
            return writes.shapedOnlyByTrusted();
        }
    }

    @Test
    void trustedRecordAllowsPublicContent() {
        assertTrue(trustedWith(PUBLISHED));
        assertTrue(trustedWith(PUBLISHED, MINE));
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

    private static final Block NAMES_NOTHING = Block.EMPTY;

    /** A guarded write to {@code owner} in a scope, at a service with {@code settings} handed {@code blocks}. */
    private ReasonCode writeHandedOn(ExtensionSettings settings, List<Block> blocks, boolean verified, String owner,
            InfluenceEntry... added) {
        List<Stamp> chain = chain("rid-1");
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(settings);
            if (blocks != null) {
                if (verified) {
                    RequestContext.markVerified(chain);
                }
                RequestContext.handOn(new HandOver(verified, chain, blocks, settings));
            }
            RequestContext.addInfluence(added);
            return writes.decide(owner);
        }
    }

    // The origin's block does not name influence, so the stamp may have read anything.
    @Test
    void aWriteWhoseOriginBlockDoesNotNameInfluenceIsDeniedWhateverItsEntries() {
        assertEquals(ReasonCode.INFLUENCE_DENIED, writeHandedOn(ACTS, List.of(NAMES_NOTHING), true, "alice", MINE));
        assertEquals(ReasonCode.INFLUENCE_DENIED, writeHandedOn(ACTS, List.of(NAMES_NOTHING), true, "alice"));
        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, List.of(Influence.block(List.of(MINE), List.of())), true,
                "alice"), "the same entries, every stamp naming influence");
    }

    @Test
    void theSameRequestAsAReadIsNot() {
        List<HandOver.StampItems> stamps = List.of(new HandOver.StampItems("gateway", null));

        assertEquals(ReasonCode.INFLUENCE_DENIED, Influence.decide(stamps, List.of(), true, "alice").reason());
        assertEquals(ReasonCode.OK, Influence.decide(stamps, List.of(), false, "alice").reason(),
                "a read is served: the write flag is what refuses");
    }

    @Test
    void untrustedWithSomeoneElsesPrivateIsDenied() {
        Block handed = Influence.block(List.of(WEB, MINE), List.of());

        assertEquals(ReasonCode.INFLUENCE_DENIED, writeHandedOn(ACTS, List.of(handed), true, "mallory"));
        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, List.of(handed), true, "alice"), "the owner's own");
    }

    @Test
    void anAddedThirdPartyFactCounts() {
        Block received = Influence.block(List.of(MINE), List.of());

        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, List.of(received), true, "bob"),
                "someone else's private alone, with nothing untrusted");
        assertEquals(ReasonCode.INFLUENCE_DENIED, writeHandedOn(ACTS, List.of(received), true, "bob", WEB));
    }

    @Test
    void nothingHandedOnReadsWhatTheServiceIsShown() {
        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, null, false, "alice"));
        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, null, false, "alice", RELAYED), "the destination owner's own");
        assertEquals(ReasonCode.INFLUENCE_DENIED, writeHandedOn(ACTS, null, false, "bob", MINE, RELAYED));
    }

    @Test
    void aTrustedRecordIsNeverWrittenFromAHandOverThatIsNotVerified() {
        List<Stamp> chain = chain("rid-1");
        Block named = Influence.block(List.of(), List.of());
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.actOn(ACTS);
            RequestContext.handOn(new HandOver(false, chain, List.of(named), ACTS));
            assertFalse(writes.shapedOnlyByTrusted(), "no verified chain");
        }
        assertTrue(trustedHandedOn(chain, List.of(named)), "the same blocks, verified");
    }

    // The guard of a service that does not act on influence would hold vacuously (no stamp is read, so every stamp
    // names it): it must refuse instead (spec influence.md, The every-stamp rule).
    @Test
    void aServiceThatDoesNotActOnInfluenceIsDeniedAGuardedWrite() {
        List<Stamp> chain = chain("rid-1");
        Block named = Influence.block(List.of(), List.of());
        ExtensionSettings other = ExtensionSettings.of(Set.of("budget"), null);
        for (ExtensionSettings settings : List.of(ExtensionSettings.NONE, other)) {
            try (RequestContext.Scope scope = RequestContext.open()) {
                RequestContext.actOn(settings);
                RequestContext.markVerified(chain);
                RequestContext.handOn(new HandOver(true, chain, List.of(named), settings));
                assertEquals(ReasonCode.INFLUENCE_DENIED, writes.decide("alice"));
                assertFalse(writes.shapedOnlyByTrusted());
            }
        }
        // The separating input: the same request at a service that acts on influence.
        assertEquals(ReasonCode.OK, writeHandedOn(ACTS, List.of(named), true, "alice"));
        assertTrue(trustedHandedOn(chain, List.of(named)));
    }
}
