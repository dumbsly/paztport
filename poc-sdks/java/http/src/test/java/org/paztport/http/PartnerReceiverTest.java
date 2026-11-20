// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;

/**
 * The partner's decision on another organisation's call, with no web framework: the session the caller names, looked
 * up for the peer its certificate names, decides whether anything is verified, and a call is believed only where it
 * verified in an attested session.
 */
class PartnerReceiverTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;
    private static final String SHOP_CA = "CN=shop CA";
    private static final byte[] REFUND = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final List<InfluenceEntry> INFLUENCE = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-ticket", "cid-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-2", "alice"));
    /** The egress's boundary block: it acts on influence, so it names it with the (blinded) entries it sends. */
    private static final Block BLOCK = Influence.block(INFLUENCE, List.of());
    /** The partner acts on influence and carries no other name. */
    private static final ExtensionSettings PARTNER = ExtensionSettings.of(Set.of(Influence.NAME),
            Set.of(Influence.NAME));

    private final KeyPair shopPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair shopKey = Crypto.generateEd25519KeyPair();
    private final KeyringFile shopKeyring = KeyringFile.sign(Map.of("orders", pub(shopKey)), pub(shopPolicy),
            NOT_AFTER, shopPolicy.getPrivate());
    private final PolicyBuilder.Result shopBuilt = PolicyBuilder.build(List.of(List.of("orders", "psp")), 4,
            NOT_AFTER, shopPolicy.getPrivate());

    private final KeyPair pspPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair pspKey = Crypto.generateEd25519KeyPair();
    private final PartnerSessions sessions = sessions(PARTNER);
    private final PartnerReceiver receiver = new PartnerReceiver(sessions, "psp");

    /** The PSP's sessions, acting on and carrying what {@code extensions} says. */
    private PartnerSessions sessions(ExtensionSettings extensions) {
        return PartnerSessions.builder()
                .ownRoot(PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, NOT_AFTER,
                        pspPolicy.getPrivate()).signedRoot())
                .ownKeyring(KeyringFile.sign(Map.of("psp", pub(pspKey)), pub(pspPolicy), NOT_AFTER,
                        pspPolicy.getPrivate()))
                .ownPolicyKey(pub(pspPolicy))
                .ownService("psp")
                .ownServiceKey(pspKey.getPrivate())
                .ownReplyCert(ReplyCert.issue(pub(pspPolicy), "psp", pub(pspKey),
                        System.currentTimeMillis() + 7 * 86_400_000L, pspPolicy.getPrivate()))
                .pinnedClientKeys(Set.of(pub(shopPolicy)))
                .clientOrigins(Set.of("orders"))
                .unsafeDisabled(List.of("POST /refund"))
                .callMaxAgeMs(5000)
                .extensions(extensions)
                .build();
    }

    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @BeforeEach
    void captureTraces() {
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
    }

    private static PeerCert cert(String issuer, String svc) {
        return new PeerCert(new Peer(svc, "10.0.0.8"), issuer);
    }

    /** An attested session opened by {@code orders} under the shop's CA. */
    private String attestedSession() {
        return attestedSession(sessions);
    }

    /** The same, in {@code in}. */
    private String attestedSession(PartnerSessions in) {
        return in.open(SessionRequest.of(shopBuilt.signedRoot(), pub(shopPolicy), shopKeyring,
                Sessions.newNonce()), SHOP_CA, "orders").sess();
    }

    /** A call from the shop's egress in {@code sess}, stamped for {@code body} and carrying {@link #BLOCK}. */
    private Map<String, String> boundary(String sess, String rid, byte[] body) {
        return boundary(sess, rid, body, BLOCK);
    }

    /** The same, its boundary stamp committing to {@code block}, which travels as its one block. */
    private Map<String, String> boundary(String sess, String rid, byte[] body, Block block) {
        List<Stamp> internal = new Stamper("gateway", "gw-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> rid, System::currentTimeMillis).next(null, "orders", "unused", Block.EMPTY, null).chain();
        Stamper.Stamped stamped = new Stamper("orders", "orders-1", shopKey.getPrivate(), false, () -> "unused",
                System::currentTimeMillis).boundary(internal, sess, "psp", RequestBinding.compute("POST", "/charge",
                        body), block, shopBuilt.bundles().get("orders"));
        Map<String, String> headers = new HashMap<>();
        headers.put(PaztportHeaders.SESSION, sess);
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
        headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
        headers.put(PaztportHeaders.EXTENSIONS, HttpWire.encodeBlocks(List.of(block)));
        return headers;
    }

    private static InboundRequest charge(Map<String, String> headers, byte[] body) {
        return new InboundRequest("POST", "/charge", headers, body);
    }

    private static String text(HttpAnswer answer) {
        return new String(answer.json(), StandardCharsets.UTF_8);
    }

    /** The request lines, without the handshakes' own. */
    private List<String> traceLines() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(line -> line.startsWith("PAZTPORT_TRACE request ")).toList();
    }

    @Test
    void aPartnerCallHasNoDeliveryInTheRequestContext() {
        String sess = attestedSession();

        try (RequestContext.Entered<PartnerAccepted> entered = RequestContext.accept(receiver,
                charge(boundary(sess, "rid-1", REFUND), REFUND), cert(SHOP_CA, "orders"))) {
            assertTrue(entered.result().attested());
            assertNotNull(RequestContext.verifiedChain());
            assertNull(RequestContext.delivery(), "a delivery is named for the in-mesh receiver only");
        }
    }

    @Test
    void aCallThatVerifiesInItsAttestedSessionIsBelieved() {
        String sess = attestedSession();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertTrue(accepted.attested());
        assertEquals(1, accepted.verifiedChain().size(), "the boundary stamp alone");
        assertEquals("rid-1", accepted.verifiedChain().get(0).rid());
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=psp ✓ peer=orders (mTLS) "
                + "classes=private,third-party session=attested"), traceLines());
    }

    @Test
    void anAttestedCallHandsOverItsOneBlock() {
        String sess = attestedSession();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertTrue(accepted.handOver().verified());
        assertEquals(List.of(new HandOver.StampItems("orders",
                INFLUENCE.stream().map(InfluenceEntry::toJson).toList())), accepted.handOver().under(Influence.NAME),
                "owners included");
        assertEquals(List.of(BLOCK), accepted.blocks());
    }

    /** sessions.md, Over HTTP: in an unsafe session nothing is believed, so nothing is handed on and no block read. */
    @Test
    void anUnsafeCallHandsNothingOverWhateverItsBlocks() {
        String sess = sessions.open(SessionRequest.of(null, pub(shopPolicy), shopKeyring, Sessions.newNonce()),
                SHOP_CA, "orders").sess();
        Map<String, String> altered = boundary(sess, "rid-1", REFUND);
        altered.put(PaztportHeaders.EXTENSIONS, HttpWire.encodeBlocks(List.of(Influence.block(List.of(), List.of()))));

        PartnerAccepted accepted = receiver.accept(charge(altered, REFUND), cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal(), "served: check 9a does not reach an unsafe session");
        assertFalse(accepted.attested());
        assertNull(accepted.handOver());
        assertNull(accepted.blocks());
    }

    /** The partner's settings reach its session verifiers: a name outside its allowed list is check 9b's. */
    @Test
    void aPartnerVerifiesWithItsOwnSettings() {
        String sess = attestedSession();
        Block example = Block.of(Map.of("example", List.of("1")), List.of());

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND, example), REFUND),
                cert(SHOP_CA, "orders"));

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"EXTENSION_NOT_ALLOWED\"}", text(accepted.refusal()));
    }

    @Test
    void aCallThatFailsInItsSessionIsRefusedWithItsCode() {
        String sess = attestedSession();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND),
                "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), cert(SHOP_CA, "orders"));

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"BINDING_MISMATCH\"}", text(accepted.refusal()));
        assertFalse(accepted.attested());
        assertNull(accepted.verifiedChain());
    }

    // With no X-Path-Session the caller never opened a session: unsafe, so whatever headers came are not believed,
    // even a call that would verify in a session the peer holds.
    @Test
    void noSessionHeaderIsUnsafeAndBelievesNothing() {
        Map<String, String> call = boundary(attestedSession(), "rid-1", REFUND);
        call.remove(PaztportHeaders.SESSION);

        PartnerAccepted accepted = receiver.accept(charge(call, REFUND), cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertFalse(accepted.attested());
        assertNull(accepted.verifiedChain());
        assertNull(accepted.handOver());
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=- receiver=psp peer=orders (mTLS) "
                + "session=unsafe"), traceLines());
    }

    // A blank header is read as no header, as every Paztport header is (spec wire.md, HTTP): it asks for nothing an
    // absent one does not, since a caller can always leave the header out.
    @Test
    void aBlankSessionHeaderIsNoHeader() {
        Map<String, String> call = boundary(attestedSession(), "rid-1", REFUND);
        for (String blank : List.of("", " ", "\t")) {
            traces.list.clear();
            call.put(PaztportHeaders.SESSION, blank);

            PartnerAccepted accepted = receiver.accept(charge(call, REFUND), cert(SHOP_CA, "orders"));

            String shown = "[" + blank + "]";
            assertNull(accepted.refusal(), shown);
            assertFalse(accepted.attested(), shown);
            assertNull(accepted.verifiedChain(), shown);
            assertNull(accepted.handOver(), shown);
            assertNull(accepted.result(), shown);
            assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=- receiver=psp peer=orders (mTLS) "
                    + "session=unsafe"), traceLines(), shown);
        }
    }

    // Only spaces and tabs are blank: a no-break space or a vertical tab is a value, and names no session.
    @Test
    void aSessionHeaderOfNbspNamesNoSession() {
        Map<String, String> call = boundary(attestedSession(), "rid-1", REFUND);
        for (String value : List.of("\u00a0", "\u000b")) {
            call.put(PaztportHeaders.SESSION, value);

            PartnerAccepted accepted = receiver.accept(charge(call, REFUND), cert(SHOP_CA, "orders"));

            String shown = String.format("U+%04X", (int) value.charAt(0));
            assertNotNull(accepted.refusal(), shown + " is a value, never taken as unsafe");
            assertEquals(403, accepted.refusal().status(), shown);
            assertEquals("{\"reason\":\"SESSION_UNKNOWN\"}", text(accepted.refusal()), shown);
            assertFalse(accepted.attested(), shown);
        }
    }

    // The spaces and tabs around a value are not part of it, as HTTP reads every field value.
    @Test
    void aLiveSessionIdWrappedInSpacesAndTabsNamesThatSession() {
        String sess = attestedSession();
        Map<String, String> call = boundary(sess, "rid-1", REFUND);
        call.put(PaztportHeaders.SESSION, " \t" + sess + "\t ");

        PartnerAccepted accepted = receiver.accept(charge(call, REFUND), cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertTrue(accepted.attested());
        assertEquals(ReasonCode.OK, accepted.result().reason());
    }

    @Test
    void anUnknownSessionIdIsStillRefused() {
        attestedSession(); // the peer holds a live session, but not the one it names

        PartnerAccepted accepted = receiver.accept(charge(boundary("no-such-session", "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertNotNull(accepted.refusal(), "an id that names no session is never taken as unsafe");
        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"SESSION_UNKNOWN\"}", text(accepted.refusal()));
        assertFalse(accepted.attested());
    }

    @Test
    void aSessionOpenedUnsafeBelievesNothing() {
        String sess = sessions.open(SessionRequest.of(null, pub(shopPolicy), shopKeyring, Sessions.newNonce()),
                SHOP_CA, "orders").sess();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertFalse(accepted.attested());
        assertNull(accepted.handOver());
    }

    // Naming a session that is not this peer's is refused, never stepped down to unsafe.
    @Test
    void aSessionThisPeerDidNotOpenIsRefusedAndNeverTakenAsUnsafe() {
        String sess = attestedSession();
        Map<String, String> call = boundary(sess, "rid-1", REFUND);
        List<PeerCert> others = new ArrayList<>(List.of(cert(SHOP_CA, "gateway"),
                cert("CN=foreign CA", "orders")));
        others.add(null);
        for (PeerCert other : others) {
            PartnerAccepted accepted = receiver.accept(charge(call, REFUND), other);

            assertEquals(403, accepted.refusal().status(), String.valueOf(other));
            assertEquals("{\"reason\":\"SESSION_UNKNOWN\"}", text(accepted.refusal()));
            assertFalse(accepted.attested());
        }
        PartnerAccepted unknown = receiver.accept(charge(boundary("no-such-session", "rid-2", REFUND), REFUND),
                cert(SHOP_CA, "orders"));
        assertEquals("{\"reason\":\"SESSION_UNKNOWN\"}", text(unknown.refusal()));
        assertEquals("PAZTPORT_TRACE request rid=rid-2 reason=SESSION_UNKNOWN receiver=psp ✗ peer=orders (mTLS) "
                + "classes=- session=unknown", traceLines().get(traceLines().size() - 1));
    }

    @Test
    void anAttestedCallReportsTheSessionVerifiersResult() {
        String sess = attestedSession();

        PartnerAccepted served = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));
        PartnerAccepted refused = receiver.accept(charge(boundary(sess, "rid-2", REFUND),
                "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), cert(SHOP_CA, "orders"));

        assertEquals(ReasonCode.OK, served.result().reason());
        assertNotNull(refused.refusal());
        assertEquals(ReasonCode.BINDING_MISMATCH, refused.result().reason());
    }

    @Test
    void nothingIsReportedInAnUnsafeSessionOrForAnUnknownOne() {
        Map<String, String> noSession = boundary(attestedSession(), "rid-1", REFUND);
        noSession.remove(PaztportHeaders.SESSION);
        String unsafe = sessions.open(SessionRequest.of(null, pub(shopPolicy), shopKeyring, Sessions.newNonce()),
                SHOP_CA, "orders").sess();

        assertNull(receiver.accept(charge(noSession, REFUND), cert(SHOP_CA, "orders")).result());
        assertNull(receiver.accept(charge(boundary(unsafe, "rid-2", REFUND), REFUND), cert(SHOP_CA, "orders"))
                .result());
        PartnerAccepted unknown = receiver.accept(charge(boundary("no-such-session", "rid-3", REFUND), REFUND),
                cert(SHOP_CA, "orders"));
        assertNotNull(unknown.refusal());
        assertNull(unknown.result(), "the unknown-session result the trace line builds is not exposed");
    }

    @Test
    void anItemThatIsNotAnEntryIs400InfluenceMismatch() {
        String sess = attestedSession();
        Block unread = Block.of(Map.of(Influence.NAME, List.of("\"not an entry\"")), List.of());

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND, unread), REFUND),
                cert(SHOP_CA, "orders"));

        assertEquals(400, accepted.refusal().status());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()));
        assertFalse(accepted.attested(), "an item that does not read is believed by no one");
    }

    /**
     * spec intent.md, Anything across the boundary: the origin's facts do not cross, and an item in the boundary
     * block would be the egress's own statement, read as the first stamp's. So a partner that acts on intent refuses
     * any item under it, though the item reads and the call verified, and a block that names intent with none is
     * served. A partner that does not act on intent reads nothing under it, and carries the item as before.
     */
    @Test
    void aPartnerThatActsOnIntentRefusesAnyIntentItem() {
        ExtensionSettings both = ExtensionSettings.of(Set.of(Influence.NAME, Intent.NAME),
                Set.of(Influence.NAME, Intent.NAME));
        PartnerSessions intentSessions = sessions(both);
        PartnerReceiver actsOnIntent = new PartnerReceiver(intentSessions, "psp");
        String facts = IntentFacts.builder().put("amount", 100).build().toItem();
        Block stated = Block.of(Map.of(Influence.NAME, List.of(), Intent.NAME, List.of(facts)), List.of());
        Block named = Block.of(Map.of(Influence.NAME, List.of(), Intent.NAME, List.of()), List.of());
        String sess = attestedSession(intentSessions);

        PartnerAccepted refused = actsOnIntent.accept(charge(boundary(sess, "rid-1", REFUND, stated), REFUND),
                cert(SHOP_CA, "orders"));
        assertEquals(400, refused.refusal().status());
        assertEquals("{\"reason\":\"INTENT_MISMATCH\"}", text(refused.refusal()));
        assertFalse(refused.attested(), "an item at the boundary is believed by no one");

        PartnerAccepted served = actsOnIntent.accept(charge(boundary(sess, "rid-2", REFUND, named), REFUND),
                cert(SHOP_CA, "orders"));
        assertNull(served.refusal());
        assertTrue(served.attested());
        assertEquals(List.of(new HandOver.StampItems("orders", List.of())), served.handOver().under(Intent.NAME));

        PartnerSessions carrying = sessions(ExtensionSettings.of(Set.of(Influence.NAME),
                Set.of(Influence.NAME, Intent.NAME)));
        PartnerAccepted carried = new PartnerReceiver(carrying, "psp").accept(charge(boundary(
                attestedSession(carrying), "rid-3", REFUND, stated), REFUND), cert(SHOP_CA, "orders"));
        assertNull(carried.refusal());
        assertTrue(carried.attested());
        assertNull(carried.handOver().under(Intent.NAME), "read by no one");
        assertEquals(List.of(stated), carried.blocks());
    }

    /** A call refused for an intent item opens no scope that holds facts: the handler is never reached. */
    @Test
    void aPartnerThatActsOnIntentHandsNoFactsToTheContext() {
        PartnerSessions intentSessions = sessions(ExtensionSettings.of(Set.of(Intent.NAME), null));
        String facts = IntentFacts.builder().put("amount", 100).build().toItem();
        Block stated = Block.of(Map.of(Intent.NAME, List.of(facts)), List.of());
        Block named = Block.of(Map.of(Intent.NAME, List.of()), List.of());
        OriginIntent intent = new OriginIntent("psp");
        String sess = attestedSession(intentSessions);
        PartnerReceiver actsOnIntent = new PartnerReceiver(intentSessions, "psp");

        try (RequestContext.Entered<PartnerAccepted> entered = RequestContext.accept(actsOnIntent,
                charge(boundary(sess, "rid-1", REFUND, stated), REFUND), cert(SHOP_CA, "orders"))) {
            assertNotNull(entered.result().refusal());
            assertNull(RequestContext.handedOn());
            assertEquals(IntentFacts.NONE, intent.facts());
        }
        try (RequestContext.Entered<PartnerAccepted> entered = RequestContext.accept(actsOnIntent,
                charge(boundary(sess, "rid-2", REFUND, named), REFUND), cert(SHOP_CA, "orders"))) {
            assertTrue(entered.result().attested());
            assertEquals(IntentFacts.NONE, intent.facts());
            assertEquals(ReasonCode.INTENT_MISSING, intent.require(List.of("amount")));
        }
    }
}
