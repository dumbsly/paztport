// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.NonceCacheUnavailableException;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;

/**
 * The receiver's decision on one request, with no web framework: what it refuses and with which body, what the
 * handler starts from, which events and trace lines it gives, and when and over what it attests. The servlet half
 * (the body cache, the scope around the handler, the wrapper that holds the body for {@link Accepted#attest}, the
 * async path and the control-plane skip) is the starter's, and is tested there.
 */
class HttpReceiverTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PAID = "paid".getBytes(StandardCharsets.UTF_8);
    private static final InfluenceEntry WEB = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:a", "h1", null, null);
    private static final InfluenceEntry MINE = new InfluenceEntry(InfluenceClass.PRIVATE, "db:a", "h2", null, "alice");

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

    private final CollectingPublisher events = new CollectingPublisher();
    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");
    private final ListAppender<ILoggingEvent> warnings = new ListAppender<>();
    private final Logger receiverLog = (Logger) LoggerFactory.getLogger(HttpReceiver.class);

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

    @AfterEach
    void releaseReceiverLog() {
        receiverLog.detachAppender(warnings);
        receiverLog.setLevel(null);
        receiverLog.setAdditive(true);
    }

    private Verifier paymentVerifier() {
        return paymentVerifier(new InMemoryNonceCache());
    }

    private Verifier paymentVerifier(NonceCache nonces) {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                nonces, () -> NOW, 5000, 5000));
    }

    /** A cache that cannot answer, as a shared store that is down. */
    private static final NonceCache DOWN = new NonceCache() {
        @Override
        public boolean seenBefore(String key, long now) {
            throw new IllegalStateException("store at 10.1.2.3 down");
        }

        @Override
        public long ttlMs() {
            return 10_000;
        }
    };

    /** Payment verifying requests under the mode, with no stamp key, so it never attests. */
    private HttpReceiver verifying(ReceivedRequestListener listener) {
        return HttpReceiver.builder("payment").verifier(paymentVerifier()).verifyRequests(true).publisher(events)
                .listener(listener).build();
    }

    /** A hop that neither verifies requests nor holds a verifier or a stamp key. */
    private static HttpReceiver plain() {
        return HttpReceiver.builder("payment").build();
    }

    private Stamper paymentStamper() {
        return new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW);
    }

    /** Payment verifying requests and holding a stamp key, so it attests what it answers to a verified chain. */
    private HttpReceiver attesting(Verifier verifier) {
        return HttpReceiver.builder("payment").verifier(verifier).verifyRequests(true).publisher(events)
                .stamper(paymentStamper()).build();
    }

    /**
     * Payment not verifying requests ({@code paztport.verify=false}) but holding a verifier and a stamp key, as
     * orders and search do in the mesh: it checks a chain only to decide whether to attest.
     */
    private HttpReceiver nonEnforcing(Verifier verifier) {
        return HttpReceiver.builder("payment").verifier(verifier).stamper(paymentStamper()).build();
    }

    /** A one-stamp chain claiming to come from the origin {@code gateway}, for {@code payment}, under {@code sig}. */
    private static String forgedChain(String rid, String sig) {
        return HttpWire.encodeChain(List.of(new Stamp("gateway", "gw-1", rid, NOW, "", "payment",
                RequestBinding.compute("POST", "/pay", TO_PAYMENT), Influence.commit(List.of()), "", sig)));
    }

    /** The two forgeries anyone can write without a key: an empty signature, and well-formed garbage. */
    private static final List<String> FORGED_SIGS = List.of("", Base64Url.encode(new byte[64]));

    private record Headers(String chain, String proof, String influence) {
    }

    private Headers headers(String rid, String target, List<InfluenceEntry> influence) {
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", target, TO_PAYMENT), influence,
                        policy.bundles().get("orders"));
        return new Headers(HttpWire.encodeChain(ord.chain()), HttpWire.encodeProof(ord.proof()),
                HttpWire.encodeInfluence(influence));
    }

    private Headers validHeaders() {
        return headers("rid-1", "/pay", List.of());
    }

    private static InboundRequest request(String method, String target, Headers h, byte[] body) {
        Map<String, String> sent = new HashMap<>();
        if (h.chain() != null) {
            sent.put(PaztportHeaders.CHAIN, h.chain());
        }
        if (h.proof() != null) {
            sent.put(PaztportHeaders.PROOF, h.proof());
        }
        if (h.influence() != null) {
            sent.put(PaztportHeaders.INFLUENCE, h.influence());
        }
        return new InboundRequest(method, target, sent, body);
    }

    private static InboundRequest paymentRequest(Headers h, byte[] body) {
        return request("POST", "/pay", h, body);
    }

    private static final Headers NONE = new Headers(null, null, null);

    private static String text(HttpAnswer answer) {
        return new String(answer.json(), StandardCharsets.UTF_8);
    }

    private static List<ContentLabel> alicesData() {
        return List.of(ContentLabel.fresh(InfluenceClass.PRIVATE, "alice"));
    }

    private static JsonNode decodeAttestation(String header) throws Exception {
        return new ObjectMapper().readTree(HttpWire.decodeChain(header));
    }

    /** The attestation's labels as the SDK reads them from the header token: their JCS text. */
    private static String labelsText(String header) {
        return JsonWriter.text(JsonFields.object(JsonReader.token(header)).get("labels"));
    }

    private static Stamp responseStamp(String header) throws Exception {
        return Chains.parse(new ObjectMapper().createArrayNode()
                .add(decodeAttestation(header).get("stamp")).toString()).stamps().get(0);
    }

    private List<String> traceLines() {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private static final class CollectingPublisher implements EventPublisher {
        final List<AttestationEvent> all = new ArrayList<>();

        @Override
        public void publish(AttestationEvent event) {
            all.add(event);
        }
    }

    // --- Operations ---

    private final PolicyBuilder.Result opsPolicy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders#getOrder"), List.of("gateway", "orders")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

    /** Orders verifying requests under the operations policy, holding a stamp key, so it attests what verifies. */
    private HttpReceiver ordersVerifying() {
        long notAfter = opsPolicy.signedRoot().notAfter();
        Verifier verifier = new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic())), notAfter)),
                List.of(new PinnedRoot(opsPolicy.signedRoot().rootBytes(), opsPolicy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "", new InMemoryNonceCache(), () -> NOW, 5000, 5000));
        return HttpReceiver.builder("orders").verifier(verifier).verifyRequests(true).publisher(events)
                .stamper(new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)).build();
    }

    /** A request from gateway to orders, whose stamp names {@code named}, with the operation the framework chose. */
    private InboundRequest toOrders(String rid, String named, String operation) {
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, named, RequestBinding.compute("GET", "/orders/123", new byte[0]), List.of(),
                        opsPolicy.bundles().get("gateway"));
        Map<String, String> sent = new HashMap<>();
        sent.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(gw.chain()));
        sent.put(PaztportHeaders.PROOF, HttpWire.encodeProof(gw.proof()));
        return new InboundRequest("GET", "/orders/123", sent, new byte[0], operation);
    }

    @Test
    void confirmsTheDispatchedOperation() {
        Accepted ok = ordersVerifying().accept(toOrders("rid-1", "orders#getOrder", "getOrder"), null,
                VerificationMode.ENFORCE);
        assertNull(ok.refusal());
        assertTrue(ok.attests());
        assertEquals("getOrder", ok.operation(), "the operation the request was verified as received by");

        for (String operation : new String[] {"createOrder", null}) {
            Accepted other = ordersVerifying().accept(toOrders("rid-2", "orders#getOrder", operation), null,
                    VerificationMode.ENFORCE);
            assertEquals(403, other.refusal().status());
            assertEquals("{\"reason\":\"BINDING_MISMATCH\"}", text(other.refusal()));
        }
    }

    @Test
    void chainNamingNoOperationGetsTheBareName() {
        Accepted accepted = ordersVerifying().accept(toOrders("rid-1", "orders", "getOrder"), null,
                VerificationMode.ENFORCE);

        assertNull(accepted.refusal(), "it verifies against gateway/orders");
        assertNull(accepted.operation(), "no operation was confirmed, whatever is dispatched");
    }

    @Test
    void anOperationIsConfirmedOnlyWhereTheLiveOrderRanWithIt() {
        Accepted off = ordersVerifying().accept(toOrders("rid-1", "orders#getOrder", "getOrder"), null,
                VerificationMode.OFF);
        assertNull(off.operation(), "nothing was verified");

        Accepted audited = ordersVerifying().accept(toOrders("rid-2", "orders#getOrder", "createOrder"), null,
                VerificationMode.AUDIT);
        assertEquals("createOrder", audited.operation(), "verified with it, though the chain named another");
    }

    @Test
    void auditServesAMisnamedOperation() {
        Accepted accepted = ordersVerifying().accept(toOrders("rid-1", "orders#getOrder", "createOrder"), null,
                VerificationMode.AUDIT);

        assertNull(accepted.refusal());
        assertNull(accepted.verifiedChain());
        assertEquals(1, events.all.size());
        assertEquals("BINDING_MISMATCH", events.all.get(0).reason());
        assertEquals(true, events.all.get(0).audit());
        assertFalse(accepted.attests(), "an unverified chain is not attested");
    }

    @Test
    void traceNamesTheReceiverWithItsOperation() {
        ordersVerifying().accept(toOrders("rid-1", "orders#getOrder", "getOrder"), null, VerificationMode.ENFORCE);

        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=orders#getOrder \u2713 peer=none"
                + " classes=-"), traceLines());
    }

    @Test
    void enforceValidRequestPassesWithTheVerifiedInfluence() {
        Accepted accepted = verifying(null).accept(
                paymentRequest(headers("rid-1", "/pay", List.of(MINE, WEB)), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertNull(accepted.refusal());
        assertEquals(2, accepted.inbound().size());
        assertEquals(accepted.inbound(), accepted.verifiedChain(), "it passed the live order here");
        assertEquals(List.of(MINE, WEB), accepted.influence());
        assertTrue(events.all.isEmpty(), "no event on success");
    }

    @Test
    void theRawTargetIsWhatIsBound() {
        Accepted bound = verifying(null).accept(request("POST", "/pay?id=7", headers("rid-1", "/pay?id=7",
                List.of()), TO_PAYMENT), null, VerificationMode.ENFORCE);
        assertNull(bound.refusal());

        Accepted other = verifying(null).accept(request("POST", "/pay?id=8", headers("rid-2", "/pay?id=7",
                List.of()), TO_PAYMENT), null, VerificationMode.ENFORCE);
        assertEquals(403, other.refusal().status());
        assertEquals("{\"reason\":\"BINDING_MISMATCH\"}", text(other.refusal()));
    }

    @Test
    void enforceTamperedBodyIsRefused403AndPublishesANonAuditEvent() {
        Accepted accepted = verifying(null).accept(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes()),
                null, VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"BINDING_MISMATCH\"}", text(accepted.refusal()));
        assertEquals(1, events.all.size());
        assertEquals("BINDING_MISMATCH", events.all.get(0).reason());
        assertEquals(false, events.all.get(0).audit());
        assertEquals("rid-1", events.all.get(0).rid());
    }

    @Test
    void enforceAlteredInfluenceIsRefusedWithInfluenceMismatch() {
        Headers h = headers("rid-1", "/pay", List.of(MINE));
        Headers altered = new Headers(h.chain(), h.proof(), HttpWire.encodeInfluence(List.of(WEB)));

        Accepted accepted = verifying(null).accept(paymentRequest(altered, TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()));
        assertEquals("INFLUENCE_MISMATCH", events.all.get(0).reason());
    }

    @Test
    void enforceMissingHeadersAreRefusedWithChainMissing() {
        Accepted accepted = verifying(null).accept(paymentRequest(NONE, TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"CHAIN_MISSING\"}", text(accepted.refusal()));
        assertEquals("CHAIN_MISSING", events.all.get(0).reason());
    }

    /** A stamp's JSON in the wire table's member order, not JCS's. */
    private static String wireOrder(Stamp s) {
        return "{\"v\":3,\"svc\":\"" + s.svc() + "\",\"inst\":\"" + s.inst() + "\",\"rid\":\"" + s.rid()
                + "\",\"ts\":" + s.ts() + ",\"sess\":\"" + s.sess() + "\",\"rcv\":\"" + s.rcv()
                + "\",\"bind\":\"" + s.bind() + "\",\"infl\":\"" + s.infl() + "\",\"prev\":\"" + s.prev()
                + "\",\"sig\":\"" + s.sig() + "\"}";
    }

    @Test
    void aChainInWireMemberOrderIsChainMissing() {
        Headers valid = validHeaders();
        List<Stamp> sent = Chains.parse(HttpWire.decodeChain(valid.chain())).stamps();
        String text = "[" + String.join(",", sent.stream().map(HttpReceiverTest::wireOrder).toList()) + "]";
        Headers h = new Headers(Base64Url.encode(text.getBytes(StandardCharsets.UTF_8)), valid.proof(),
                valid.influence());

        Accepted accepted = verifying(null).accept(paymentRequest(h, TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"CHAIN_MISSING\"}", text(accepted.refusal()));
        assertEquals("CHAIN_MISSING", events.all.get(0).reason());
        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=- reason=CHAIN_MISSING receiver=payment ✗ peer=none classes=-"),
                traceLines());
    }

    @Test
    void auditModePassesATamperedRequestWithTheReceivedInfluence() {
        Accepted accepted = verifying(null).accept(
                paymentRequest(headers("rid-1", "/pay", List.of(MINE)), "{\"amount\":999}".getBytes()), null,
                VerificationMode.AUDIT);

        assertNull(accepted.refusal(), "audit always passes through");
        assertNull(accepted.verifiedChain(), "but nothing verified");
        assertEquals(List.of(MINE), accepted.influence(), "what was received still counts towards the rule");
        assertEquals(1, events.all.size());
        assertEquals("BINDING_MISMATCH", events.all.get(0).reason());
        assertEquals(true, events.all.get(0).audit());
    }

    @Test
    void offModeSkipsVerificationEntirely() {
        Accepted accepted = verifying(null).accept(paymentRequest(NONE, TO_PAYMENT), null, VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertTrue(events.all.isEmpty(), "off mode publishes nothing");
        assertTrue(traceLines().isEmpty(), "and verifies nothing, so traces nothing");
    }

    private List<String> receiverWarnings() {
        return warnings.list.stream().filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void captureReceiverLog() {
        warnings.start();
        receiverLog.addAppender(warnings);
        receiverLog.setLevel(Level.WARN);
        receiverLog.setAdditive(false);
    }

    @Test
    void enforceRefuses503WhenTheNonceCacheCannotAnswer() {
        captureReceiverLog();
        HttpReceiver receiver = HttpReceiver.builder("payment").verifier(paymentVerifier(DOWN))
                .verifyRequests(true).publisher(events).stamper(paymentStamper()).build();

        Accepted accepted = receiver.accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertEquals(503, accepted.refusal().status());
        assertEquals(0, accepted.refusal().json().length, "an empty body");
        assertEquals(IllegalStateException.class, accepted.cacheFailure().getCause().getClass());
        assertNull(accepted.verifiedChain());
        assertFalse(accepted.attests());
        assertNull(accepted.delivery());
        assertTrue(events.all.isEmpty(), "no verdict, so no event");
        assertEquals(List.of("nonce cache unavailable: " + IllegalStateException.class.getName()),
                receiverWarnings(), "the cause's class and nothing else");
        assertTrue(warnings.list.get(0).getThrowableProxy() == null, "no stack trace");
    }

    @Test
    void auditServesUnverifiedWhenTheNonceCacheCannotAnswer() {
        captureReceiverLog();
        HttpReceiver receiver = HttpReceiver.builder("payment").verifier(paymentVerifier(DOWN))
                .verifyRequests(true).publisher(events).stamper(paymentStamper()).build();

        Accepted accepted = receiver.accept(paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT),
                null, VerificationMode.AUDIT);

        assertNull(accepted.refusal());
        assertNotNull(accepted.cacheFailure());
        assertNull(accepted.verifiedChain());
        assertFalse(accepted.attests());
        assertNull(accepted.delivery());
        assertEquals(List.of(WEB), accepted.influence(), "what was received still counts towards the rule");
        assertEquals(1, receiverWarnings().size());
    }

    /** A cache that cannot answer and counts how often it is asked. */
    private static final class CountingDown implements NonceCache {
        int asked;

        @Override
        public boolean seenBefore(String key, long now) {
            asked++;
            throw new IllegalStateException("store down");
        }

        @Override
        public long ttlMs() {
            return 10_000;
        }
    }

    @Test
    void aCacheThatIsDownNeverMasksInfluenceThatCannotBeReadUnderEnforce() {
        CountingDown cache = new CountingDown();
        Headers h = validHeaders();
        HttpReceiver receiver = HttpReceiver.builder("payment").verifier(paymentVerifier(cache))
                .verifyRequests(true).publisher(events).build();

        Accepted accepted = receiver.accept(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT),
                null, VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()));
        assertNull(accepted.cacheFailure());
        assertNull(accepted.verifiedChain());
        assertFalse(accepted.attests());
        assertEquals(1, events.all.size());
        assertEquals("INFLUENCE_MISMATCH", events.all.get(0).reason());
        assertEquals(0, cache.asked, "verification refuses before the nonce cache is asked");
    }

    @Test
    void aCacheThatIsDownNeverMasksInfluenceThatCannotBeReadUnderAudit() {
        CountingDown cache = new CountingDown();
        Headers h = validHeaders();
        HttpReceiver receiver = HttpReceiver.builder("payment").verifier(paymentVerifier(cache))
                .verifyRequests(true).publisher(events).build();

        Accepted accepted = receiver.accept(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT),
                null, VerificationMode.AUDIT);

        assertEquals(400, accepted.refusal().status());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()));
        assertNull(accepted.cacheFailure());
        assertNull(accepted.verifiedChain());
        assertFalse(accepted.attests());
        assertEquals(1, events.all.size());
        assertEquals("INFLUENCE_MISMATCH", events.all.get(0).reason());
        assertEquals(0, cache.asked, "verification fails before the nonce cache is asked");
    }

    @Test
    void aReceiverWithNoModeServesUnattestedWhenTheNonceCacheCannotAnswer() {
        captureReceiverLog();
        HttpReceiver receiver = HttpReceiver.builder("payment").verifier(paymentVerifier(DOWN))
                .stamper(paymentStamper()).build();

        Accepted accepted = receiver.accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertFalse(accepted.attests());
        assertNotNull(accepted.cacheFailure());
        assertNull(accepted.verifiedChain());
        assertNull(accepted.delivery());
        assertEquals(1, receiverWarnings().size());
    }

    @Test
    void aHealthyCacheLeavesNoFailureAndAVerifiedRequestNamesItsDelivery() {
        Accepted accepted = verifying(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertNull(accepted.cacheFailure());
        List<Stamp> chain = accepted.verifiedChain();
        assertEquals(new Delivery(chain.get(0).rid(), "orders", RequestBinding.compute("POST", "/pay", TO_PAYMENT)),
                accepted.delivery());
        assertEquals(new Delivery("rid-1", chain.get(chain.size() - 1).svc(), chain.get(chain.size() - 1).bind()),
                accepted.delivery());
    }

    @Test
    void thereIsNoDeliveryForAnOriginAnOffHopOrAnAuditFailure() {
        HttpReceiver origin = HttpReceiver.builder("payment").verifier(paymentVerifier()).verifyRequests(true)
                .publisher(events).origin(true).build();
        assertNull(origin.accept(paymentRequest(validHeaders(), TO_PAYMENT), null, VerificationMode.ENFORCE)
                .delivery());
        assertNull(verifying(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), null, VerificationMode.OFF)
                .delivery());
        assertNull(verifying(null).accept(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes()), null,
                VerificationMode.AUDIT).delivery());
    }

    @Test
    void aRegisteredListenerIsCalledOncePerRequestWithTheReceivedValues() {
        List<Object[]> calls = new ArrayList<>();
        Headers h = headers("rid-1", "/pay", List.of(WEB));

        verifying((chain, proof, influence, method, target, body) ->
                calls.add(new Object[] {chain, proof, influence, method, target, body}))
                .accept(request("POST", "/pay?id=7", h, TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertEquals(1, calls.size());
        Object[] call = calls.get(0);
        assertEquals(h.chain(), call[0]);
        assertEquals(h.proof(), call[1]);
        assertEquals(h.influence(), call[2]);
        assertEquals("POST", call[3]);
        assertEquals("/pay?id=7", call[4]);
        assertArrayEquals(TO_PAYMENT, (byte[]) call[5]);
    }

    @Test
    void theListenerSeesARequestThatVerificationThenRefuses() {
        List<String> order = new ArrayList<>();

        Accepted accepted = verifying((chain, proof, influence, method, target, body) -> order.add("listener"))
                .accept(paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), null,
                        VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals(List.of("listener"), order, "called before verification, even for a request that fails it");
    }

    @Test
    void headersAreFoundInAnyCase() {
        Headers h = validHeaders();
        Accepted accepted = verifying(null).accept(new InboundRequest("POST", "/pay", Map.of(
                "x-path-chain", h.chain(), "X-PATH-PROOF", h.proof()), TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertNull(accepted.refusal());
    }

    @Test
    void aNonVerifyingReceiverCarriesTheHeadersAsReceived() {
        Accepted accepted = plain().accept(paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT),
                null, VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertEquals(2, accepted.inbound().size());
        assertEquals("rid-1", accepted.inbound().get(0).rid());
        assertNull(accepted.verifiedChain(), "nothing was checked");
        assertEquals(List.of(WEB), accepted.influence());
        assertTrue(traceLines().isEmpty(), "nothing was verified");
    }

    @Test
    void aNonVerifyingReceiverAnswersMalformedInfluenceWith400() {
        Headers h = validHeaders();

        Accepted accepted = plain().accept(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT),
                null, VerificationMode.OFF);

        assertEquals(400, accepted.refusal().status());
        assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()),
                "influence that cannot be carried must not be dropped");
    }

    @Test
    void anUnreadableChainLeavesNoInboundChain() {
        Accepted accepted = plain().accept(paymentRequest(new Headers("not-a-chain", null, null), TO_PAYMENT),
                null, VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertNull(accepted.inbound());
    }

    @Test
    void everyVerificationLogsOneTraceLine() {
        verifying(null).accept(paymentRequest(headers("rid-1", "/pay", List.of(WEB, MINE)), TO_PAYMENT), null,
                VerificationMode.ENFORCE);
        verifying(null).accept(paymentRequest(headers("rid-2", "/pay", List.of()), "{}".getBytes()), null,
                VerificationMode.ENFORCE);

        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=private,third-party",
                "PAZTPORT_TRACE request rid=rid-2 reason=BINDING_MISMATCH receiver=payment ✗ peer=none classes=-"),
                traceLines());
    }

    @Test
    void theTraceLineKeepsAForgedRidOnOneLine() {
        verifying(null).accept(paymentRequest(headers("r\nPAZTPORT_TRACE request reason=OK", "/pay", List.of()),
                TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertEquals(1, traceLines().size());
        assertTrue(traceLines().get(0).startsWith("PAZTPORT_TRACE request rid=r\\u000aPAZTPORT_TRACE"),
                traceLines().get(0));
    }

    @Test
    void theTraceLineNamesTheAuthenticatedPeer() {
        verifying(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), new Peer("orders", "10.0.0.4"),
                VerificationMode.ENFORCE);

        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=orders (mTLS) "
                + "classes=-"), traceLines());
    }

    // A refusal is for the caller, who is usually the suspect: the body is the reason alone. The suspect, with
    // whatever inst it signed, goes to the event; the trace line, with no peer here, names no suspect.
    @Test
    void theRefusalBodyIsTheReasonAloneWhateverTheSuspectSigned() {
        String inst = "ord\"1\\";
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "rid-1", () -> NOW)
                .next(null, "orders", "b", List.of(), policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", inst, orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), List.of(),
                        policy.bundles().get("orders"));

        // No proof, so the route is unproven and the last signer, with its chosen inst, is the suspect.
        Accepted accepted = verifying(null).accept(
                paymentRequest(new Headers(HttpWire.encodeChain(ord.chain()), null, null), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"PATH_NOT_ALLOWED\"}", text(accepted.refusal()));
        assertEquals(1, events.all.size());
        assertEquals("orders", events.all.get(0).suspectSvc());
        assertEquals(inst, events.all.get(0).suspectInst());
        assertEquals(1, traceLines().size());
        assertTrue(traceLines().get(0).contains(" reason=PATH_NOT_ALLOWED receiver=payment ✗ peer=none "),
                traceLines().get(0));
    }

    @Test
    void auditAndOffModesStillAnswerMalformedInfluenceWith400() {
        Headers h = validHeaders();
        for (VerificationMode mode : List.of(VerificationMode.AUDIT, VerificationMode.OFF)) {
            for (HttpReceiver hop : List.of(verifying(null), attesting(paymentVerifier()))) {
                Accepted accepted = hop.accept(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT),
                        null, mode);

                assertEquals(400, accepted.refusal().status(), mode.name());
                assertEquals("{\"reason\":\"INFLUENCE_MISMATCH\"}", text(accepted.refusal()), mode.name());
            }
        }
    }

    /**
     * {@code OFF} on a verifier is the operator turning Paztport off on that hop: nothing is checked, so nothing is
     * vouched for, even for a chain that would verify. What the handler is given is unchanged, so its own calls are
     * stamped as in any other mode.
     */
    @Test
    void aVerifierSwitchedOffVerifiesNothingAndAttestsNothing() {
        Accepted accepted = attesting(paymentVerifier()).accept(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), null, VerificationMode.OFF);

        assertNull(accepted.refusal(), "served");
        assertFalse(accepted.attests(), "a chain that would verify, but nothing checked it");
        assertNull(accepted.attest(201, PAID, alicesData()));
        assertNull(accepted.verifiedChain());
        assertTrue(traceLines().isEmpty(), "no verification ran, not even one for attestation alone");
        assertTrue(events.all.isEmpty());
        assertEquals(2, accepted.inbound().size(), "the inbound chain is carried for outbound stamping");
        assertEquals(List.of(WEB), accepted.influence(), "and so is the influence received");
    }

    @Test
    void theModeIsReadPerRequest() {
        HttpReceiver hop = attesting(paymentVerifier());
        List<Boolean> attested = new ArrayList<>();
        int rid = 0;
        for (VerificationMode mode : List.of(VerificationMode.ENFORCE, VerificationMode.OFF,
                VerificationMode.ENFORCE, VerificationMode.OFF)) {
            Accepted accepted = hop.accept(paymentRequest(headers("rid-" + ++rid, "/pay", List.of()), TO_PAYMENT),
                    null, mode);
            assertNull(accepted.refusal(), mode.name());
            attested.add(accepted.attest(201, PAID, List.of()) != null);
        }

        assertEquals(List.of(true, false, true, false), attested);
        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=-",
                "PAZTPORT_TRACE request rid=rid-3 reason=OK receiver=payment ✓ peer=none classes=-"),
                traceLines(), "verified only while enforcing");
    }

    @Test
    void aReceiverThatDoesNotVerifyRequestsHasNoModeToSwitch() {
        assertThrows(IllegalArgumentException.class, () -> nonEnforcing(paymentVerifier())
                .accept(paymentRequest(validHeaders(), TO_PAYMENT), null, VerificationMode.ENFORCE));
        assertThrows(NullPointerException.class, () -> verifying(null)
                .accept(paymentRequest(validHeaders(), TO_PAYMENT), null, null));
    }

    @Test
    void aVerifiedRequestsResponseIsAttestedOverTheStatusBodyAndLabelsGiven() throws Exception {
        Accepted accepted = attesting(paymentVerifier()).accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertTrue(accepted.attests());
        String header = accepted.attest(201, PAID, alicesData());
        List<ContentLabel> labels = ContentLabel.parseAll(labelsText(header));
        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.PRIVATE, labels.get(0).cls());
        assertEquals("alice", labels.get(0).owner());
        Stamp stamp = responseStamp(header);
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv(), "the response goes back to whoever called");
        assertEquals("rid-1", stamp.rid());
        assertEquals(Bindings.response(HttpWire.resultHash(201, PAID), "rid-1", labels), stamp.bind());
    }

    @Test
    void aVerifiedRequestIsVerifiedOnceForBothTheModeAndTheAttestation() {
        attesting(paymentVerifier()).accept(paymentRequest(validHeaders(), TO_PAYMENT), null, VerificationMode.ENFORCE);

        // A second run would spend the request's nonce again and come back REPLAY.
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=-"),
                traceLines());
    }

    @Test
    void aServiceThatDoesNotVerifyRequestsAttestsAChainThatVerifiesHere() throws Exception {
        Accepted first = nonEnforcing(paymentVerifier()).accept(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), null, VerificationMode.OFF);
        Accepted second = nonEnforcing(paymentVerifier()).accept(
                paymentRequest(headers("rid-2", "/pay", List.of(WEB)), TO_PAYMENT), null, VerificationMode.OFF);

        Stamp stamp = responseStamp(first.attest(201, PAID, List.of()));
        assertEquals("payment", stamp.svc());
        assertEquals("orders", stamp.rcv());
        assertEquals(first.inbound(), first.verifiedChain(), "verified here, for attestation");
        assertEquals(List.of(
                "PAZTPORT_TRACE request rid=rid-1 reason=OK receiver=payment ✓ peer=none classes=third-party",
                "PAZTPORT_TRACE request rid=rid-2 reason=OK receiver=payment ✓ peer=none classes=third-party"),
                traceLines(), "checked once each, for attestation alone");
        assertEquals(List.of(WEB), second.influence(), "the influence is still carried");
        assertEquals(2, second.inbound().size());
    }

    /**
     * A response stamp is request-shaped: on a one-stamp chain, it would be a valid origin stamp from this service.
     * So a forged chain, which anyone can write, must never be attested, whether or not the hop enforces.
     */
    @Test
    void aForgedChainIsNeverAttestedButStillServedWhereRequestsAreNotVerified() {
        for (String sig : FORGED_SIGS) {
            for (HttpReceiver hop : List.of(nonEnforcing(paymentVerifier()), attesting(paymentVerifier()))) {
                Accepted accepted = hop.accept(paymentRequest(new Headers(forgedChain("rid-" + sig, sig), null,
                        null), TO_PAYMENT), null, VerificationMode.OFF);

                assertNull(accepted.refusal(), "sig=\"" + sig + "\": not refused");
                assertFalse(accepted.attests(), "sig=\"" + sig + "\": nothing minted");
                assertNull(accepted.attest(201, PAID, List.of()), "sig=\"" + sig + "\"");
                assertNull(accepted.verifiedChain());
            }
        }
        assertTrue(events.all.isEmpty(), "checking for attestation publishes nothing");
        // Only the hop that does not verify requests checks the chain; the one switched off checks nothing.
        assertEquals(2, traceLines().size());
        for (String line : traceLines()) {
            assertTrue(line.contains(" reason=BAD_SIGNATURE receiver=payment ✗ "), line);
        }
    }

    /**
     * The attack this guards against: a compromised service sends the origin a forged one-stamp chain naming
     * another service as its sender. Were it attested, the origin's response stamp would be a genuine origin stamp
     * addressed to that service, ready to start a chain it never sent. The origin attests nothing, so there is no
     * stamp to drive the next hop with.
     */
    @Test
    void anOriginNeverAttestsAForgedChain() {
        Stamper gatewayStamper = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> "r", () -> NOW);
        for (String sig : FORGED_SIGS) {
            String forged = HttpWire.encodeChain(List.of(new Stamp("orders", "x", "R", NOW, "", "x", "b",
                    Influence.commit(List.of()), "", sig)));
            for (Verifier verifier : Arrays.asList(null, paymentVerifier())) {
                Accepted accepted = HttpReceiver.builder("gateway").verifier(verifier).origin(true)
                        .stamper(gatewayStamper).build()
                        .accept(request("GET", "/find", new Headers(forged, null, null), new byte[0]), null,
                                VerificationMode.OFF);

                assertNull(accepted.refusal());
                assertFalse(accepted.attests(), "sig=\"" + sig + "\": nothing minted");
            }
        }
    }

    @Test
    void anOriginNeverAttestsAndStartsFromNothingEvenWhenTheChainVerifies() {
        Stamper ordersAsOrigin = new Stamper("orders", "ord-1", orders.getPrivate(), true, () -> "r", () -> NOW);
        for (boolean verify : new boolean[] {true, false}) {
            Accepted accepted = HttpReceiver.builder("payment").verifier(paymentVerifier()).verifyRequests(verify)
                    .origin(true).publisher(events).stamper(ordersAsOrigin).build()
                    .accept(paymentRequest(headers("rid-" + verify, "/pay", List.of(MINE)), TO_PAYMENT), null,
                            verify ? VerificationMode.ENFORCE : VerificationMode.OFF);

            assertNull(accepted.refusal(), "verify=" + verify);
            assertNull(accepted.inbound(), "verify=" + verify + ": an origin starts a new tree");
            assertNull(accepted.verifiedChain(), "verify=" + verify);
            assertEquals(List.of(), accepted.influence(),
                    "verify=" + verify + ": and carries no influence it was sent");
            assertFalse(accepted.attests(), "verify=" + verify);
        }
        assertEquals(List.of("PAZTPORT_TRACE request rid=rid-true reason=OK receiver=payment ✓ peer=none "
                + "classes=private"), traceLines(), "verified under the mode, and not again for attestation");
    }

    @Test
    void anOriginIgnoresUnreadableInfluence() {
        Headers h = validHeaders();

        Accepted accepted = HttpReceiver.builder("payment").origin(true).build()
                .accept(paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), null,
                        VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertEquals(List.of(), accepted.influence(), "an origin carries none, so none is dropped");
    }

    @Test
    void aServiceWithAStampKeyButNoVerifierNeverAttests() {
        Accepted accepted = nonEnforcing(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertFalse(accepted.attests(), "it cannot know the chain is good");
    }

    @Test
    void verifyingRequestsNeedsAVerifierAndAPublisher() {
        assertThrows(IllegalArgumentException.class,
                () -> HttpReceiver.builder("payment").verifyRequests(true).publisher(events).build());
        assertThrows(IllegalArgumentException.class,
                () -> HttpReceiver.builder("payment").verifyRequests(true).verifier(paymentVerifier()).build());
    }

    @Test
    void aPeerWhoseCertificateNamesNoServiceIsShownQuoted() {
        String line = HttpReceiver.traceLine("rid-1", new VerifyResult(ReasonCode.PEER_MISMATCH, "", "10.0.0.9"),
                "payment", new Peer("", "10.0.0.9"), List.of());

        assertEquals("PAZTPORT_TRACE request rid=rid-1 reason=PEER_MISMATCH receiver=payment ✗ peer=\"\" (mTLS) "
                + "classes=-", line);
    }

    @Test
    void anAuditFailureIsServedButNotAttested() {
        Accepted accepted = attesting(paymentVerifier()).accept(
                paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), null,
                VerificationMode.AUDIT);

        assertNull(accepted.refusal(), "audit passes the request through");
        assertFalse(accepted.attests(), "but vouches for nothing it answered");
    }

    @Test
    void aRefusalIsNotAttested() {
        Accepted accepted = attesting(paymentVerifier()).accept(
                paymentRequest(validHeaders(), "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)), null,
                VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertFalse(accepted.attests());
        assertNull(accepted.attest(403, accepted.refusal().json(), List.of()));
    }

    @Test
    void withoutAnInboundChainThereIsNothingToAttestOnto() {
        Accepted accepted = nonEnforcing(paymentVerifier()).accept(paymentRequest(NONE, TO_PAYMENT), null,
                VerificationMode.OFF);

        assertNull(accepted.refusal());
        assertFalse(accepted.attests());
    }

    @Test
    void aRidTheResponseBindingCannotCarryIsLeftUnattestedWithAWarning() {
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger receiverLog = (Logger) LoggerFactory.getLogger(HttpReceiver.class);
        warnings.start();
        receiverLog.addAppender(warnings);
        receiverLog.setLevel(Level.WARN);
        receiverLog.setAdditive(false);
        try {
            // Signed and verified, but a newline cannot be a response's call id.
            Accepted accepted = attesting(paymentVerifier()).accept(
                    paymentRequest(headers("r\nx", "/pay", List.of()), TO_PAYMENT), null, VerificationMode.ENFORCE);

            assertTrue(accepted.attests());
            assertNull(accepted.attest(201, PAID, List.of()));
            assertEquals(1, warnings.list.size());
            String warning = warnings.list.get(0).getFormattedMessage();
            assertTrue(warning.startsWith("response left unattested: rid=r\\u000ax "), warning);
        } finally {
            receiverLog.detachAppender(warnings);
            receiverLog.setLevel(null);
            receiverLog.setAdditive(true);
        }
    }

    @Test
    void theAnswerHandsOutCopiesOfItsBody() {
        Accepted accepted = verifying(null).accept(paymentRequest(NONE, TO_PAYMENT), null, VerificationMode.ENFORCE);

        accepted.refusal().json()[0] = 'x';

        assertEquals("{\"reason\":\"CHAIN_MISSING\"}", text(accepted.refusal()));
        assertNotNull(HttpAnswer.refusal(403, ReasonCode.UNSAFE_SESSION));
        assertEquals("{\"reason\":\"UNSAFE_SESSION\"}", text(HttpAnswer.refusal(403, ReasonCode.UNSAFE_SESSION)));
    }

    private static final byte[] TAMPERED = "{\"amount\":999}".getBytes(StandardCharsets.UTF_8);

    @Test
    void enforceReportsTheResultItServedOn() {
        Accepted accepted = verifying(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.ENFORCE);

        assertNull(accepted.refusal());
        assertEquals(ReasonCode.OK, accepted.result().reason());
    }

    @Test
    void enforceReportsTheResultItRefusedFor() {
        Accepted missing = verifying(null).accept(paymentRequest(NONE, TO_PAYMENT), null, VerificationMode.ENFORCE);
        Accepted tampered = verifying(null).accept(paymentRequest(validHeaders(), TAMPERED), null,
                VerificationMode.ENFORCE);

        assertNotNull(missing.refusal());
        assertEquals(ReasonCode.CHAIN_MISSING, missing.result().reason());
        assertNotNull(tampered.refusal());
        assertEquals(ReasonCode.BINDING_MISMATCH, tampered.result().reason());
    }

    // Under enforce the verification runs first, so influence it cannot read fails it: the 403, not the 400.
    @Test
    void enforceRefusesUnreadableInfluenceAsItsVerificationFailure() {
        Headers h = validHeaders();

        Accepted accepted = verifying(null).accept(
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), null, VerificationMode.ENFORCE);

        assertEquals(403, accepted.refusal().status());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH, accepted.result().reason());
    }

    @Test
    void auditReportsTheResultOfARequestItServes() {
        Accepted good = verifying(null).accept(paymentRequest(validHeaders(), TO_PAYMENT), null,
                VerificationMode.AUDIT);
        Accepted bad = verifying(null).accept(paymentRequest(validHeaders(), TAMPERED), null,
                VerificationMode.AUDIT);

        assertNull(bad.refusal());
        assertEquals(ReasonCode.OK, good.result().reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, bad.result().reason());
    }

    @Test
    void auditReportsTheResultOfARequestItRefusesForUnreadableInfluence() {
        Headers h = validHeaders();

        Accepted accepted = verifying(null).accept(
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%"), TO_PAYMENT), null, VerificationMode.AUDIT);

        assertEquals(400, accepted.refusal().status());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH, accepted.result().reason());
    }

    @Test
    void anOriginThatVerifiesReportsItsResult() {
        Accepted accepted = HttpReceiver.builder("payment").verifier(paymentVerifier()).verifyRequests(true)
                .origin(true).publisher(events).build()
                .accept(paymentRequest(NONE, TO_PAYMENT), null, VerificationMode.AUDIT);

        assertEquals(ReasonCode.CHAIN_MISSING, accepted.result().reason());
    }

    @Test
    void attestationAloneReportsItsResult() {
        Accepted good = nonEnforcing(paymentVerifier()).accept(
                paymentRequest(headers("rid-1", "/pay", List.of(WEB)), TO_PAYMENT), null, VerificationMode.OFF);
        Accepted forged = nonEnforcing(paymentVerifier()).accept(
                paymentRequest(new Headers(forgedChain("rid-2", ""), null, null), TO_PAYMENT), null,
                VerificationMode.OFF);

        assertEquals(ReasonCode.OK, good.result().reason());
        assertEquals(ReasonCode.BAD_SIGNATURE, forged.result().reason());
    }

    @Test
    void nothingIsReportedWhereNothingWasVerified() {
        Headers valid = validHeaders();
        Headers unreadable = new Headers(valid.chain(), valid.proof(), "%%%");

        assertNull(verifying(null).accept(paymentRequest(valid, TO_PAYMENT), null, VerificationMode.OFF).result(),
                "switched off");
        assertNull(attesting(paymentVerifier()).accept(paymentRequest(valid, TO_PAYMENT), null,
                VerificationMode.OFF).result(), "switched off, with a stamp key");
        assertNull(plain().accept(paymentRequest(valid, TO_PAYMENT), null, VerificationMode.OFF).result(),
                "a hop that verifies nothing");
        assertNull(HttpReceiver.builder("payment").build()
                .accept(paymentRequest(valid, TO_PAYMENT), null, VerificationMode.OFF).result());
        assertNull(HttpReceiver.builder("payment").verifier(paymentVerifier()).stamper(paymentStamper())
                .origin(true).build().accept(paymentRequest(valid, TO_PAYMENT), null, VerificationMode.OFF).result(),
                "an origin that does not verify");
        assertNull(nonEnforcing(paymentVerifier()).accept(paymentRequest(NONE, TO_PAYMENT), null,
                VerificationMode.OFF).result(), "no chain, so nothing ran");
        Accepted refused = verifying(null).accept(paymentRequest(unreadable, TO_PAYMENT), null,
                VerificationMode.OFF);
        assertEquals(400, refused.refusal().status());
        assertNull(refused.result(), "unreadable influence, with nothing verified");
    }
}
