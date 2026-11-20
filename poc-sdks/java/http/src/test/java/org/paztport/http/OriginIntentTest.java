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
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.ReasonCode;
import org.slf4j.LoggerFactory;

/**
 * What a handler at payment reads of the origin's facts, from the request's context: the facts only from a verified
 * hand-over, the core's answer to what it requires, and a trace line that names the request and its last signer but
 * never a fact's value.
 */
class OriginIntentTest {

    private static final ExtensionSettings ACTS_ON_INTENT = ExtensionSettings.of(Set.of(Intent.NAME), null);
    private static final IntentFacts FACTS = IntentFacts.builder().put("amount", 100).put("order", "123").build();
    private static final Block ORIGIN = Block.of(Map.of(Intent.NAME, List.of(FACTS.toItem())), List.of());
    private static final Block UNREAD = Block.of(Map.of(Intent.NAME, List.of("{\"facts\":{}}")), List.of());

    private final PrivateKey key = Crypto.generateEd25519KeyPair().getPrivate();
    /** gateway, the origin, to orders, then orders to payment. */
    private final List<Stamp> chain = List.of(
            Stamp.sign("gateway", "gw-1", "rid-1", 1L, "", "orders", "b", "", "", key),
            Stamp.sign("orders", "ord-1", "rid-1", 2L, "", "payment", "b", "", "", key));

    private final OriginIntent intent = new OriginIntent("payment");
    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

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
        RequestContext.reset();
    }

    private HandOver handOver(boolean verified, Block origin, ExtensionSettings settings) {
        return new HandOver(verified, chain, List.of(origin, Block.EMPTY), settings);
    }

    /** {@code read} answered in a scope holding the chain, with {@code handOver} handed on as a receiver would. */
    private <T> T inScope(HandOver handOver, Supplier<T> read) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.setInbound(chain, List.of(ORIGIN, Block.EMPTY));
            if (handOver != null && handOver.verified()) {
                TestScopes.verified(chain, handOver);
            } else if (handOver != null) {
                RequestContext.handOn(handOver);
            }
            return read.get();
        }
    }

    @Test
    void factsAreEmptyUnlessTheHandOverVerified() {
        assertEquals(FACTS, inScope(handOver(true, ORIGIN, ACTS_ON_INTENT), intent::facts));

        assertEquals(IntentFacts.NONE, intent.facts(), "outside a scope");
        assertEquals(IntentFacts.NONE, inScope(null, intent::facts), "nothing handed on");
        assertEquals(IntentFacts.NONE, inScope(handOver(false, ORIGIN, ACTS_ON_INTENT), intent::facts),
                "handed on, not verified");
        assertEquals(IntentFacts.NONE, inScope(handOver(true, UNREAD, ACTS_ON_INTENT), intent::facts),
                "verified, and the item does not read");
        assertEquals(IntentFacts.NONE, inScope(handOver(true, ORIGIN,
                ExtensionSettings.of(Set.of(Influence.NAME), null)), intent::facts),
                "a service that does not act on intent is handed nothing under it");
    }

    @Test
    void requireAnswersAsTheCoreDoes() {
        List<HandOver> handOvers = List.of(handOver(true, ORIGIN, ACTS_ON_INTENT),
                handOver(false, ORIGIN, ACTS_ON_INTENT), handOver(true, UNREAD, ACTS_ON_INTENT),
                handOver(true, Block.EMPTY, ACTS_ON_INTENT), handOver(true, ORIGIN, ExtensionSettings.NONE));
        List<List<String>> needs = List.of(List.of(), List.of("amount"), List.of("amount", "order"),
                List.of("amount", "customer"));
        for (HandOver handOver : handOvers) {
            for (List<String> need : needs) {
                assertEquals(Intent.require(handOver, need), inScope(handOver, () -> intent.require(need)),
                        handOver + " " + need);
            }
        }
        assertEquals(ReasonCode.OK, inScope(handOver(true, ORIGIN, ACTS_ON_INTENT),
                () -> intent.require(List.of("amount", "order"))));
        assertEquals(ReasonCode.INTENT_MISSING, intent.require(List.of("amount")), "outside a scope");
        assertEquals(ReasonCode.OK, intent.require(List.of()), "a handler that requires nothing");
    }

    @Test
    void denyLogsNoFactValue() {
        assertEquals(ReasonCode.INTENT_DENIED, inScope(handOver(true, ORIGIN, ACTS_ON_INTENT), intent::deny));
        assertEquals(ReasonCode.INTENT_MISSING, inScope(handOver(true, ORIGIN, ACTS_ON_INTENT),
                () -> intent.require(List.of("customer"))));
        assertEquals(ReasonCode.OK, inScope(handOver(true, ORIGIN, ACTS_ON_INTENT),
                () -> intent.require(List.of("amount"))));

        List<String> lines = traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(List.of(
                "PAZTPORT_TRACE intent rid=rid-1 receiver=payment reason=INTENT_DENIED last=orders",
                "PAZTPORT_TRACE intent rid=rid-1 receiver=payment reason=INTENT_MISSING last=orders"), lines,
                "one line for each answer that is not OK");
        for (String line : lines) {
            assertFalse(line.contains("100") || line.contains("123") || line.contains("amount"), line);
        }
        traces.list.clear();
        intent.deny();
        assertTrue(traces.list.get(0).getFormattedMessage().endsWith("rid=- receiver=payment reason=INTENT_DENIED"
                + " last=-"), "outside a scope there is no request to name");
    }
}
