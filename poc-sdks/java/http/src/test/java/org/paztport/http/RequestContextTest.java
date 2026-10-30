// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

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
import org.paztport.http.event.EventPublisher;
import org.slf4j.LoggerFactory;

class RequestContextTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final List<StampV3> chain = List.of(StampV3.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
            "", Crypto.generateEd25519KeyPair().getPrivate()));

    @AfterEach
    void cleanup() {
        RequestContext.reset();
    }

    @Test
    void storesAndClearsTheInboundChainForThisThread() {
        RequestContext.setInboundChain(chain);
        assertSame(chain, RequestContext.inboundChain());

        RequestContext.clear();
        assertNull(RequestContext.inboundChain());
    }

    @Test
    void influenceAccumulatesInOrder() {
        assertTrue(RequestContext.influence().isEmpty());
        RequestContext.addInfluence(WEB);
        RequestContext.addInfluence(MINE, WEB);
        assertEquals(List.of(WEB, MINE, WEB), RequestContext.influence());
        assertThrows(UnsupportedOperationException.class, () -> RequestContext.influence().clear());
    }

    @Test
    void labelMintsAFreshContentIdEachTime() {
        RequestContext.label(InfluenceClass.PRIVATE, "alice");
        RequestContext.label(InfluenceClass.PUBLIC, null);
        List<ContentLabel> labels = RequestContext.labels();
        assertEquals(2, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        assertNull(labels.get(1).owner());
        assertTrue(!labels.get(0).cid().equals(labels.get(1).cid()));
    }

    @Test
    void clearResetsEverything() {
        RequestContext.setInboundChain(chain);
        RequestContext.addInfluence(WEB);
        RequestContext.label(InfluenceClass.PUBLIC, null);

        RequestContext.clear();

        assertNull(RequestContext.inboundChain());
        assertTrue(RequestContext.influence().isEmpty());
        assertTrue(RequestContext.labels().isEmpty());
    }

    @Test
    void isIsolatedPerThread() throws Exception {
        RequestContext.setInboundChain(chain);
        RequestContext.addInfluence(WEB);
        Object[] seenByOther = new Object[2];

        Thread other = new Thread(() -> {
            seenByOther[0] = RequestContext.inboundChain();
            seenByOther[1] = RequestContext.influence();
        });
        other.start();
        other.join();

        assertNull(seenByOther[0], "another thread must not see this thread's chain");
        assertEquals(List.of(), seenByOther[1], "nor its influence");
    }

    @Test
    void aScopeStartsCleanAndClosingItClearsEverything() {
        RequestContext.addInfluence(WEB); // left behind by unscoped code on this thread
        assertFalse(RequestContext.isOpen());

        try (RequestContext.Scope scope = RequestContext.open()) {
            assertTrue(RequestContext.isOpen());
            assertEquals(List.of(), RequestContext.influence(), "a scope never inherits what came before it");
            RequestContext.setInboundChain(chain);
            RequestContext.addInfluence(MINE);
            RequestContext.label(InfluenceClass.PRIVATE, "alice");
        }

        assertFalse(RequestContext.isOpen());
        assertNull(RequestContext.inboundChain());
        assertTrue(RequestContext.influence().isEmpty());
        assertTrue(RequestContext.labels().isEmpty());
    }

    @Test
    void scopesDoNotNest() {
        try (RequestContext.Scope scope = RequestContext.open()) {
            assertThrows(IllegalStateException.class, RequestContext::open);
            assertTrue(RequestContext.isOpen(), "the refused open leaves the outer scope as it was");
        }
        assertFalse(RequestContext.isOpen());
    }

    @Test
    void clearEmptiesAnOpenScopeButLeavesItOpen() {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.addInfluence(WEB);
            RequestContext.clear();
            assertTrue(RequestContext.influence().isEmpty());
            assertTrue(RequestContext.isOpen());
        }
    }

    @Test
    void closingAStaleOrDuplicateScopeLeavesTheCurrentOneOpen() {
        RequestContext.Scope stale = RequestContext.open();
        stale.close();

        try (RequestContext.Scope current = RequestContext.open()) {
            RequestContext.addInfluence(WEB);
            stale.close();
            stale.close();
            assertTrue(RequestContext.isOpen(), "a scope that has ended cannot end another");
            assertEquals(List.of(WEB), RequestContext.influence());
        }
        assertFalse(RequestContext.isOpen());
    }

    @Test
    void resetEndsALeakedScopeSoANewOneCanOpen() {
        RequestContext.Scope leaked = RequestContext.open(); // never closed by the code that opened it
        RequestContext.addInfluence(WEB);

        RequestContext.reset();

        assertFalse(RequestContext.isOpen());
        assertTrue(RequestContext.influence().isEmpty());
        try (RequestContext.Scope current = RequestContext.open()) {
            leaked.close();
            assertTrue(RequestContext.isOpen(), "the leaked scope, closed late, does not end the new one");
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

        try (RequestContext.Scope scope = RequestContext.enter(accepted)) {
            assertTrue(RequestContext.isOpen());
            assertEquals(accepted.inbound(), RequestContext.inboundChain());
            assertEquals(accepted.inbound(), RequestContext.verifiedChain(), "it passed the live order here");
            assertEquals(List.of(MINE), RequestContext.influence());
        }
        assertFalse(RequestContext.isOpen());
        assertNull(RequestContext.verifiedChain());
    }

    @Test
    void aChainCarriedButNotCheckedIsNotVerified() {
        Accepted carried = HttpReceiver.builder("orders").build().accept(request(List.of(WEB)), null,
                VerificationMode.OFF);

        try (RequestContext.Scope scope = RequestContext.enter(carried)) {
            assertEquals(1, RequestContext.inboundChain().size(), "carried for the handler's calls");
            assertNull(RequestContext.verifiedChain(), "but nothing checked it");
            assertEquals(List.of(WEB), RequestContext.influence());
        }
    }

    @Test
    void aRefusalIsAnsweredNotEntered() {
        Accepted refused = verified(new InboundRequest("POST", "/x", Map.of(), BODY));

        assertThrows(IllegalArgumentException.class, () -> RequestContext.enter(refused));
        assertFalse(RequestContext.isOpen(), "no scope is opened for it");
    }

    @Test
    void enteringEndsAScopeLeakedOnThisThreadWithAWarning() {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger log = (Logger) LoggerFactory.getLogger(RequestContext.class);
        warnings.start();
        log.addAppender(warnings);
        log.setLevel(Level.WARN);
        log.setAdditive(false);
        try {
            RequestContext.Scope leaked = RequestContext.open(); // never closed by the code that opened it
            RequestContext.addInfluence(WEB);

            try (RequestContext.Scope scope = RequestContext.enter(verified(request(List.of())))) {
                assertEquals(List.of(), RequestContext.influence(), "nothing the leaked scope held is carried");
                leaked.close();
                assertTrue(RequestContext.isOpen(), "and closing it late does not end the request's own");
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
     * Only {@link RequestContext#enter}, from a receiver's result, may mark a chain verified, since the boundary
     * signer and the public-writes rule trust the chain marked, and only it may end a scope that other code opened;
     * neither may widen.
     */
    @Test
    void markVerifiedAndResetAreNotPublic() throws Exception {
        for (Method m : List.of(RequestContext.class.getDeclaredMethod("markVerified", List.class),
                RequestContext.class.getDeclaredMethod("reset"))) {
            assertFalse(Modifier.isPublic(m.getModifiers()), m.getName() + " must not be public");
            assertFalse(Modifier.isProtected(m.getModifiers()), m.getName() + " must not be protected");
        }
    }
}
