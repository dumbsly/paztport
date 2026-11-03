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
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;

class RequestContextTest {

    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final List<Stamp> chain = List.of(Stamp.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "",
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
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1",
                System::currentTimeMillis).next(null, "orders", RequestBinding.compute("POST", "/x", BODY), influence,
                policy.bundles().get("gateway"));
        Map<String, String> headers = new HashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(gw.chain()));
        headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(gw.proof()));
        headers.put(PaztportHeaders.INFLUENCE, HttpWire.encodeInfluence(influence)); // null, so unsent, when empty
        return new InboundRequest("POST", "/x", headers, BODY);
    }

    /** {@code orders} verifying requests, offering each to {@code listener} first. */
    private HttpReceiver orders(ReceivedRequestListener listener) {
        long notAfter = policy.signedRoot().notAfter();
        Verifier verifier = new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "", new InMemoryNonceCache(), System::currentTimeMillis, 5000, 5000));
        EventPublisher none = event -> {
        };
        return HttpReceiver.builder("orders").verifier(verifier).verifyRequests(true).publisher(none)
                .listener(listener).build();
    }

    /** The context's warnings, captured until {@link #releaseWarnings}. */
    private final ListAppender<ILoggingEvent> warnings = new ListAppender<>();
    private final Logger contextLog = (Logger) LoggerFactory.getLogger(RequestContext.class);

    @BeforeEach
    void captureWarnings() {
        warnings.start();
        contextLog.addAppender(warnings);
        contextLog.setLevel(Level.WARN);
        contextLog.setAdditive(false);
    }

    @AfterEach
    void releaseWarnings() {
        contextLog.detachAppender(warnings);
        contextLog.setLevel(null);
        contextLog.setAdditive(true);
    }

    @Test
    void acceptingARequestHoldsWhatItsReceiverDecidedUntilTheScopeCloses() {
        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(orders(null), request(List.of(MINE)),
                null, VerificationMode.ENFORCE)) {
            Accepted accepted = entered.result();
            assertNull(accepted.refusal());
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
        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(HttpReceiver.builder("orders").build(),
                request(List.of(WEB)), null, VerificationMode.OFF)) {
            assertNull(entered.result().refusal());
            assertEquals(1, RequestContext.inboundChain().size(), "carried for the handler's calls");
            assertNull(RequestContext.verifiedChain(), "but nothing checked it");
            assertEquals(List.of(WEB), RequestContext.influence());
        }
    }

    // The receiver runs in the request's scope: what it calls out to sees the request's chain, as the handler will.
    @Test
    void theListenerRunsInTheRequestsOwnScopeWithItsChain() {
        List<Object> seen = new ArrayList<>();

        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(orders((chain, proof, influence,
                method, target, body) -> {
            seen.add(RequestContext.isOpen());
            seen.add(RequestContext.inboundChain().get(0).rid());
            seen.add(RequestContext.verifiedChain());
        }), request(List.of()), null, VerificationMode.ENFORCE)) {
            assertNull(entered.result().refusal());
        }
        assertEquals(Arrays.asList(true, "rid-1", null), seen, "open, with its chain, not yet verified");
    }

    @Test
    void aRefusalIsAnsweredInTheRequestsScopeWhichNothingMarksVerified() {
        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(orders(null),
                new InboundRequest("POST", "/x", Map.of(), BODY), null, VerificationMode.ENFORCE)) {
            assertEquals(403, entered.result().refusal().status());
            assertTrue(RequestContext.isOpen());
            assertNull(RequestContext.verifiedChain());
            assertEquals(List.of(), RequestContext.influence());
        }
        assertFalse(RequestContext.isOpen());
    }

    // A scope leaked on this thread is ended, with a warning, before the receiver runs: the listener sees the
    // request's own scope, never the stale one.
    @Test
    void aScopeLeakedOnThisThreadIsEndedBeforeTheReceiverRuns() {
        RequestContext.Scope leaked = RequestContext.open(); // never closed by the code that opened it
        RequestContext.addInfluence(WEB);
        List<Object> seen = new ArrayList<>();

        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(orders((chain, proof, influence,
                method, target, body) -> {
            seen.add(warnings.list.size());
            seen.add(RequestContext.influence());
        }), request(List.of()), null, VerificationMode.ENFORCE)) {
            assertEquals(List.of(), RequestContext.influence(), "nothing the leaked scope held is carried");
            leaked.close();
            assertTrue(RequestContext.isOpen(), "and closing it late does not end the request's own");
        }
        assertEquals(List.of(1, List.of()), seen, "the warning came first, and the stale influence was gone");
        assertTrue(warnings.list.get(0).getFormattedMessage()
                .startsWith("a paztport context scope was leaked on thread "));
    }

    @Test
    void aRefusedRequestEndsALeakedScopeToo() {
        RequestContext.open();
        RequestContext.addInfluence(WEB);

        try (RequestContext.Entered<Accepted> entered = RequestContext.accept(orders(null),
                new InboundRequest("POST", "/x", Map.of(), BODY), null, VerificationMode.ENFORCE)) {
            assertEquals(403, entered.result().refusal().status());
        }

        assertFalse(RequestContext.isOpen(), "the thread is clean after a refusal");
        assertEquals(List.of(), RequestContext.influence());
        assertEquals(1, warnings.list.size());
    }

    @Test
    void aReceiverThatThrowsLeavesNoScopeBehind() {
        RequestContext.open();
        RequestContext.addInfluence(WEB);
        IllegalStateException fault = new IllegalStateException("listener failed");

        IllegalStateException thrown = assertThrows(IllegalStateException.class, () -> RequestContext.accept(
                orders((chain, proof, influence, method, target, body) -> {
                    throw fault;
                }), request(List.of()), null, VerificationMode.ENFORCE));

        assertSame(fault, thrown);
        assertFalse(RequestContext.isOpen(), "neither the leaked scope nor the request's own is left open");
        assertEquals(List.of(), RequestContext.influence());
        assertEquals(1, warnings.list.size());
    }

    // A checked exception thrown where the compiler cannot see it (a sneaky throw, as some libraries do) is neither
    // a RuntimeException nor an Error, and must still end the scope, or the pooled thread keeps it.
    @Test
    void aReceiverThatThrowsACheckedExceptionLeavesNoScopeBehind() {
        IOException fault = new IOException("listener failed");

        IOException thrown = assertThrows(IOException.class, () -> RequestContext.accept(
                orders((chain, proof, influence, method, target, body) -> RequestContextTest.<RuntimeException>sneak(
                        fault)), request(List.of()), null, VerificationMode.ENFORCE));

        assertSame(fault, thrown);
        assertFalse(RequestContext.isOpen(), "the request's own scope is not left open");
    }

    /** Throws {@code t} without the compiler knowing, as a sneaky-throwing library would. */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneak(Throwable t) throws T {
        throw (T) t;
    }

    /**
     * A chain is marked verified only from a receiver's result; that result is also one only a receiver can make, a
     * final class, not a record, with no constructor or factory any other code can call, so no other code can hold
     * one that says a chain verified when it did not.
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
     * Only {@link RequestContext#accept}, from the result of the receiver it ran, may mark a chain verified, since the
     * boundary signer and the public-writes rule trust the chain marked, and only it may end a scope that other code
     * opened; neither may widen. {@code current()} stays package-private too, because it lets {@code HttpCaller}
     * tell which scope a call was stamped in.
     */
    @Test
    void guardIsNotPublic() throws Exception {
        for (Method m : List.of(RequestContext.class.getDeclaredMethod("markVerified", List.class),
                RequestContext.class.getDeclaredMethod("reset"),
                RequestContext.class.getDeclaredMethod("current"))) {
            assertFalse(Modifier.isPublic(m.getModifiers()), m.getName() + " must not be public");
            assertFalse(Modifier.isProtected(m.getModifiers()), m.getName() + " must not be protected");
        }
    }
}
