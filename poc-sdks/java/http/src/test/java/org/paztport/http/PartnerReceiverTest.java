// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.Peer;
import org.paztport.http.wire.HttpV3;
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

    private final KeyPair shopPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair shopKey = Crypto.generateEd25519KeyPair();
    private final KeyringFile shopKeyring = KeyringFile.sign(Map.of("orders", pub(shopKey)), pub(shopPolicy),
            NOT_AFTER, shopPolicy.getPrivate());
    private final PolicyBuilder.Result shopBuilt = PolicyBuilder.build(List.of(List.of("orders", "psp")), 4,
            NOT_AFTER, shopPolicy.getPrivate());

    private final KeyPair pspPolicy = Crypto.generateEd25519KeyPair();
    private final KeyPair pspKey = Crypto.generateEd25519KeyPair();
    private final PartnerSessions sessions = PartnerSessions.builder()
            .ownRoot(PolicyBuilder.build(List.of(List.of("psp", "ledger")), 4, NOT_AFTER, pspPolicy.getPrivate())
                    .signedRoot())
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
            .build();
    private final PartnerReceiver receiver = new PartnerReceiver(sessions, "psp");

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
        return sessions.open(SessionRequest.of(shopBuilt.signedRoot(), pub(shopPolicy), shopKeyring,
                Sessions.newNonce()), SHOP_CA, "orders").sess();
    }

    /** A call from the shop's egress in {@code sess}, stamped for {@code body} and carrying {@link #INFLUENCE}. */
    private Map<String, String> boundary(String sess, String rid, byte[] body) {
        List<StampV3> internal = new StamperV3("gateway", "gw-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> rid, System::currentTimeMillis).next(null, "orders", "unused", List.of(), null).chain();
        StamperV3.Stamped stamped = new StamperV3("orders", "orders-1", shopKey.getPrivate(), false, () -> "unused",
                System::currentTimeMillis).boundary(internal, sess, "psp", RequestBinding.compute("POST", "/charge",
                        body), INFLUENCE, shopBuilt.bundles().get("orders"));
        Map<String, String> headers = new HashMap<>();
        headers.put(PaztportHeaders.SESSION, sess);
        headers.put(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()));
        headers.put(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
        headers.put(PaztportHeaders.INFLUENCE, HttpV3.encodeInfluence(INFLUENCE));
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
    void aCallThatVerifiesInItsAttestedSessionIsBelieved() {
        String sess = attestedSession();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertTrue(accepted.attested());
        assertEquals(1, accepted.verifiedChain().size(), "the boundary stamp alone");
        assertEquals("rid-1", accepted.verifiedChain().get(0).rid());
        assertEquals(INFLUENCE, accepted.influence(), "owners included");
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=psp ✓ peer=orders (mTLS) "
                + "classes=private,third-party session=attested"), traceLines());
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
        assertEquals(List.of(), accepted.influence());
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=- receiver=psp peer=orders (mTLS) "
                + "session=unsafe"), traceLines());
    }

    @Test
    void aSessionOpenedUnsafeBelievesNothing() {
        String sess = sessions.open(SessionRequest.of(null, pub(shopPolicy), shopKeyring, Sessions.newNonce()),
                SHOP_CA, "orders").sess();

        PartnerAccepted accepted = receiver.accept(charge(boundary(sess, "rid-1", REFUND), REFUND),
                cert(SHOP_CA, "orders"));

        assertNull(accepted.refusal());
        assertFalse(accepted.attested());
        assertEquals(List.of(), accepted.influence());
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
}
