// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.Accepted;
import org.paztport.http.HttpReceiver;
import org.paztport.http.HttpV3;
import org.paztport.http.InboundRequest;
import org.paztport.http.PartnerAccepted;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.http.VerificationMode;
import org.paztport.http.event.EventPublisher;
import org.slf4j.LoggerFactory;

class PaztportContextTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final List<StampV3> chain = List.of(StampV3.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
            "", Crypto.generateEd25519KeyPair().getPrivate()));

    @AfterEach
    void cleanup() {
        PaztportContext.reset();
    }

    @Test
    void storesAndClearsTheInboundChainForThisThread() {
        PaztportContext.setInboundChain(chain);
        assertSame(chain, PaztportContext.inboundChain());

        PaztportContext.clear();
        assertNull(PaztportContext.inboundChain());
    }

    @Test
    void influenceAccumulatesInOrder() {
        assertTrue(PaztportContext.influence().isEmpty());
        PaztportContext.addInfluence(WEB);
        PaztportContext.addInfluence(MINE, WEB);
        assertEquals(List.of(WEB, MINE, WEB), PaztportContext.influence());
        assertThrows(UnsupportedOperationException.class, () -> PaztportContext.influence().clear());
    }

    @Test
    void labelMintsAFreshContentIdEachTime() {
        PaztportContext.label(InfluenceClass.PRIVATE, "alice");
        PaztportContext.label(InfluenceClass.PUBLIC, null);
        List<ContentLabel> labels = PaztportContext.labels();
        assertEquals(2, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        assertNull(labels.get(1).owner());
        assertTrue(!labels.get(0).cid().equals(labels.get(1).cid()));
    }

    @Test
    void clearResetsEverything() {
        PaztportContext.setInboundChain(chain);
        PaztportContext.addInfluence(WEB);
        PaztportContext.label(InfluenceClass.PUBLIC, null);

        PaztportContext.clear();

        assertNull(PaztportContext.inboundChain());
        assertTrue(PaztportContext.influence().isEmpty());
        assertTrue(PaztportContext.labels().isEmpty());
    }

    @Test
    void isIsolatedPerThread() throws Exception {
        PaztportContext.setInboundChain(chain);
        PaztportContext.addInfluence(WEB);
        Object[] seenByOther = new Object[2];

        Thread other = new Thread(() -> {
            seenByOther[0] = PaztportContext.inboundChain();
            seenByOther[1] = PaztportContext.influence();
        });
        other.start();
        other.join();

        assertNull(seenByOther[0], "another thread must not see this thread's chain");
        assertEquals(List.of(), seenByOther[1], "nor its influence");
    }

    @Test
    void aScopeStartsCleanAndClosingItClearsEverything() {
        PaztportContext.addInfluence(WEB); // left behind by unscoped code on this thread
        assertFalse(PaztportContext.isOpen());

        try (PaztportContext.Scope scope = PaztportContext.open()) {
            assertTrue(PaztportContext.isOpen());
            assertEquals(List.of(), PaztportContext.influence(), "a scope never inherits what came before it");
            PaztportContext.setInboundChain(chain);
            PaztportContext.addInfluence(MINE);
            PaztportContext.label(InfluenceClass.PRIVATE, "alice");
        }

        assertFalse(PaztportContext.isOpen());
        assertNull(PaztportContext.inboundChain());
        assertTrue(PaztportContext.influence().isEmpty());
        assertTrue(PaztportContext.labels().isEmpty());
    }

    @Test
    void scopesDoNotNest() {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            assertThrows(IllegalStateException.class, PaztportContext::open);
            assertTrue(PaztportContext.isOpen(), "the refused open leaves the outer scope as it was");
        }
        assertFalse(PaztportContext.isOpen());
    }

    @Test
    void clearEmptiesAnOpenScopeButLeavesItOpen() {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(WEB);
            PaztportContext.clear();
            assertTrue(PaztportContext.influence().isEmpty());
            assertTrue(PaztportContext.isOpen());
        }
    }

    @Test
    void closingAStaleOrDuplicateScopeLeavesTheCurrentOneOpen() {
        PaztportContext.Scope stale = PaztportContext.open();
        stale.close();

        try (PaztportContext.Scope current = PaztportContext.open()) {
            PaztportContext.addInfluence(WEB);
            stale.close();
            stale.close();
            assertTrue(PaztportContext.isOpen(), "a scope that has ended cannot end another");
            assertEquals(List.of(WEB), PaztportContext.influence());
        }
        assertFalse(PaztportContext.isOpen());
    }

    @Test
    void resetEndsALeakedScopeSoANewOneCanOpen() {
        PaztportContext.Scope leaked = PaztportContext.open(); // never closed by the code that opened it
        PaztportContext.addInfluence(WEB);

        PaztportContext.reset();

        assertFalse(PaztportContext.isOpen());
        assertTrue(PaztportContext.influence().isEmpty());
        try (PaztportContext.Scope current = PaztportContext.open()) {
            leaked.close();
            assertTrue(PaztportContext.isOpen(), "the leaked scope, closed late, does not end the new one");
        }
    }

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;
    private static final byte[] BODY = "{}".getBytes(StandardCharsets.UTF_8);

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4,
            NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());

    /** A request from {@code gateway} to {@code orders}, stamped, proven and carrying {@code influence}. */
    private InboundRequest request(List<InfluenceEntry> influence) {
        StamperV3.Stamped gw = new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1",
                System::currentTimeMillis).next(null, "orders", RequestBinding.compute("POST", "/x", BODY), influence,
                policy.bundles().get("gateway"));
        Map<String, String> headers = new HashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpV3.encodeChain(gw.chain()));
        headers.put(PaztportHeaders.PROOF, HttpV3.encodeProof(gw.proof()));
        headers.put(PaztportHeaders.INFLUENCE, HttpV3.encodeInfluence(influence)); // null, so unsent, when empty
        return new InboundRequest("POST", "/x", headers, BODY);
    }

    /** What {@code orders} decides about {@code request} when it verifies requests and enforces. */
    private Accepted verified(InboundRequest request) {
        VerifierV3 verifier = new VerifierV3(new VerifierConfigV3(Keyring.of(Map.of("gateway", gateway.getPublic())),
                policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), policy.signedRoot().notAfter(),
                Set.of("gateway"), "", new InMemoryNonceCache(), System::currentTimeMillis, 5000, 5000));
        EventPublisher none = event -> {
        };
        return HttpReceiver.builder("orders").verifier(verifier).verifyRequests(true).publisher(none).build()
                .accept(request, null, VerificationMode.ENFORCE);
    }

    @Test
    void enteringARequestHoldsWhatItsReceiverDecidedUntilTheScopeCloses() {
        Accepted accepted = verified(request(List.of(MINE)));

        try (PaztportContext.Scope scope = PaztportContext.enter(accepted)) {
            assertTrue(PaztportContext.isOpen());
            assertEquals(accepted.inbound(), PaztportContext.inboundChain());
            assertEquals(accepted.inbound(), PaztportContext.verifiedChain(), "it passed the live order here");
            assertEquals(List.of(MINE), PaztportContext.influence());
        }
        assertFalse(PaztportContext.isOpen());
        assertNull(PaztportContext.verifiedChain());
    }

    @Test
    void aChainCarriedButNotCheckedIsNotVerified() {
        Accepted carried = HttpReceiver.builder("orders").build().accept(request(List.of(WEB)), null,
                VerificationMode.OFF);

        try (PaztportContext.Scope scope = PaztportContext.enter(carried)) {
            assertEquals(1, PaztportContext.inboundChain().size(), "carried for the handler's calls");
            assertNull(PaztportContext.verifiedChain(), "but nothing checked it");
            assertEquals(List.of(WEB), PaztportContext.influence());
        }
    }

    @Test
    void aRefusalIsAnsweredNotEntered() {
        Accepted refused = verified(new InboundRequest("POST", "/x", Map.of(), BODY));

        assertThrows(IllegalArgumentException.class, () -> PaztportContext.enter(refused));
        assertFalse(PaztportContext.isOpen(), "no scope is opened for it");
    }

    @Test
    void enteringEndsAScopeLeakedOnThisThreadWithAWarning() {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger log = (Logger) LoggerFactory.getLogger(PaztportContext.class);
        warnings.start();
        log.addAppender(warnings);
        log.setLevel(Level.WARN);
        log.setAdditive(false);
        try {
            PaztportContext.Scope leaked = PaztportContext.open(); // never closed by the code that opened it
            PaztportContext.addInfluence(WEB);

            try (PaztportContext.Scope scope = PaztportContext.enter(verified(request(List.of())))) {
                assertEquals(List.of(), PaztportContext.influence(), "nothing the leaked scope held is carried");
                leaked.close();
                assertTrue(PaztportContext.isOpen(), "and closing it late does not end the request's own");
            }
            assertEquals(1, warnings.list.size());
            assertTrue(warnings.list.get(0).getFormattedMessage()
                    .startsWith("a paztport context scope was leaked on thread "));
        } finally {
            log.detachAppender(warnings);
            log.setLevel(null);
            log.setAdditive(true);
        }
    }

    /**
     * A chain is marked verified only from a receiver's result, so that result must be one only a receiver can make:
     * a final class, not a record, with no constructor or factory any other code can call.
     */
    @Test
    void theResultsThatMarkAChainVerifiedCannotBeMadeOutsideTheReceivers() {
        for (Class<?> type : List.of(Accepted.class, PartnerAccepted.class)) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type.getSimpleName() + " must be final");
            assertFalse(type.isRecord(), type.getSimpleName() + " must not be a record");
            for (Constructor<?> c : type.getDeclaredConstructors()) {
                assertTrue(Modifier.isPrivate(c.getModifiers()), type.getSimpleName() + ": " + c);
            }
            for (Method m : type.getDeclaredMethods()) {
                boolean makesOne = Modifier.isStatic(m.getModifiers()) && m.getReturnType() == type;
                assertFalse(makesOne && (Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers())),
                        type.getSimpleName() + ": " + m);
            }
        }
    }

    /**
     * Only {@link PaztportContext#enter}, from a receiver's result, may mark a chain verified, since the boundary
     * signer and the public-writes rule trust the chain marked, and only it may end a scope that other code opened;
     * neither may widen.
     */
    @Test
    void markVerifiedAndResetAreNotPublic() throws Exception {
        for (Method m : List.of(PaztportContext.class.getDeclaredMethod("markVerified", List.class),
                PaztportContext.class.getDeclaredMethod("reset"))) {
            assertFalse(Modifier.isPublic(m.getModifiers()), m.getName() + " must not be public");
            assertFalse(Modifier.isProtected(m.getModifiers()), m.getName() + " must not be protected");
        }
    }
}
