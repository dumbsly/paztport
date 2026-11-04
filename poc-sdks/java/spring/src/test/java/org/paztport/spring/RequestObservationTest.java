// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static io.micrometer.observation.tck.TestObservationRegistryAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.tck.TestObservationRegistry;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.ContextAccess;
import org.paztport.http.HttpSessions;
import org.paztport.http.ModeHolder;
import org.paztport.http.PartnerSessions;
import org.paztport.http.PeerCert;
import org.paztport.http.ReceivedRequestListener;
import org.paztport.http.RequestContext;
import org.paztport.http.VerificationMode;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * What the two inbound filters record about each request: one observation, named for the filter, tagged with the
 * mode or the session, the verification result's reason and whether the request was served or refused, and stopped
 * before the handler runs. Nothing from the request is ever a tag. What is decided, and so what is recorded, is
 * {@code InboundFilterTest}'s and {@code PartnerRequestTest}'s; the cases here read the registry.
 */
class RequestObservationTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final String SHOP_CERTIFICATE = "tls/orders.crt";
    private static final byte[] TO_PAYMENT = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CHARGE = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    /** The words a tag value may be besides a reason code's name. */
    private static final Set<String> FIXED = Set.of("none", "off", "audit", "enforce", "served", "refused",
            "attested", "unsafe", "unknown");

    private final TestObservationRegistry registry = TestObservationRegistry.create();
    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair orders = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment"), List.of("gateway", "orders")), 4, NOT_AFTER,
            Crypto.generateEd25519KeyPair().getPrivate());

    @AfterEach
    void cleanup() {
        ContextAccess.reset();
    }

    /** A registry whose one handler throws {@code failure} as each observation stops, as a faulty handler might. */
    private static ObservationRegistry throwingOnStop(RuntimeException failure) {
        return throwing(null, failure);
    }

    /**
     * A registry whose one handler throws {@code onScopeClosed}, where it is not null, as an observation's scope
     * closes, and {@code onStop} as the observation stops, as a faulty handler might.
     */
    private static ObservationRegistry throwing(RuntimeException onScopeClosed, RuntimeException onStop) {
        ObservationRegistry throwing = ObservationRegistry.create();
        throwing.observationConfig().observationHandler(new ObservationHandler<>() {
            @Override
            public void onScopeClosed(Observation.Context context) {
                if (onScopeClosed != null) {
                    throw onScopeClosed;
                }
            }

            @Override
            public void onStop(Observation.Context context) {
                throw onStop;
            }

            @Override
            public boolean supportsContext(Observation.Context context) {
                return true;
            }
        });
        return throwing;
    }

    // The shop's side -----------------------------------------------------------------------------------------

    private Verifier paymentVerifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(), () -> NOW, 5000, 5000));
    }

    private InboundFilter filter(VerificationMode mode, ReceivedRequestListener listener) {
        return new InboundFilter(paymentVerifier(), true, false, "payment", new ModeHolder(mode), event -> { },
                listener, null, registry);
    }

    private InboundFilter attestingFilter(boolean verifyRequests) {
        return new InboundFilter(paymentVerifier(), verifyRequests, false, "payment",
                verifyRequests ? new ModeHolder(VerificationMode.ENFORCE) : null, verifyRequests ? event -> { } : null,
                null, new Stamper("payment", "pay-1", payment.getPrivate(), false, () -> "x", () -> NOW), registry);
    }

    private record Headers(String chain, String proof, String influence) {
    }

    private Headers headers(String rid, List<InfluenceEntry> influence) {
        Stamper.Stamped gw = new Stamper("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, () -> NOW)
                .next(null, "orders", RequestBinding.compute("POST", "/orders", "{}".getBytes()), List.of(),
                        policy.bundles().get("gateway"));
        Stamper.Stamped ord = new Stamper("orders", "ord-1", orders.getPrivate(), false, () -> "x", () -> NOW)
                .next(gw.chain(), "payment", RequestBinding.compute("POST", "/pay", TO_PAYMENT), influence,
                        policy.bundles().get("orders"));
        return new Headers(HttpWire.encodeChain(ord.chain()), HttpWire.encodeProof(ord.proof()),
                HttpWire.encodeInfluence(influence));
    }

    private Headers validHeaders() {
        return headers("rid-1", List.of());
    }

    private static MockHttpServletRequest paymentRequest(Headers h) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        if (h.chain() != null) {
            request.addHeader(PaztportHeaders.CHAIN, h.chain());
        }
        if (h.proof() != null) {
            request.addHeader(PaztportHeaders.PROOF, h.proof());
        }
        if (h.influence() != null) {
            request.addHeader(PaztportHeaders.INFLUENCE, h.influence());
        }
        request.setContent(TO_PAYMENT);
        return request;
    }

    private static MockHttpServletResponse run(InboundFilter filter, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    // The partner's side --------------------------------------------------------------------------------------

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
            .callMaxAgeMs(5000)
            .build();
    private final PartnerFilter partnerFilter = new PartnerFilter(sessions, "psp", registry);

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** The fixture certificate of the shop's egress, which the partner's mutual TLS would have authenticated. */
    private static X509Certificate shopCertificate() throws Exception {
        try (InputStream in = RequestObservationTest.class.getClassLoader().getResourceAsStream(SHOP_CERTIFICATE)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    /** Opens a session as the shop's egress: attested with the shop's root, unsafe without one. */
    private String handshake(boolean withRoot) throws Exception {
        SessionRequest req = SessionRequest.of(withRoot ? shopBuilt.signedRoot() : null, pub(shopPolicy), shopKeyring,
                Sessions.newNonce());
        byte[] reply = HttpSessions.serve(new ByteArrayInputStream(req.toJson().getBytes(StandardCharsets.UTF_8)),
                PeerCert.of(shopCertificate(), "127.0.0.1"), sessions).json();
        return new ObjectMapper().readTree(reply).get("sess").asText();
    }

    /** A boundary call to {@code /charge} in {@code sess}; {@code sent} is the body it carries, bound or not. */
    private MockHttpServletRequest charge(String sess, byte[] sent) throws Exception {
        List<Stamp> internal = new Stamper("gateway", "gw-1", Crypto.generateEd25519KeyPair().getPrivate(), true,
                () -> "rid-1", System::currentTimeMillis).next(null, "orders", "unused", List.of(), null).chain();
        Stamper.Stamped stamped = new Stamper("orders", "orders-1", shopKey.getPrivate(), false, () -> "unused",
                System::currentTimeMillis).boundary(internal, sess, "psp",
                        RequestBinding.compute("POST", "/charge", CHARGE), List.of(),
                        shopBuilt.bundles().get("orders"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/charge");
        request.addHeader(PaztportHeaders.SESSION, sess);
        request.addHeader(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            request.addHeader(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
        }
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[] {shopCertificate()});
        request.setContent(sent);
        return request;
    }

    private MockHttpServletResponse serve(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        partnerFilter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    // The shop's observations ---------------------------------------------------------------------------------

    @Test
    void enforceRecordsOkAndServed() throws Exception {
        MockHttpServletResponse response = run(filter(VerificationMode.ENFORCE, null), paymentRequest(validHeaders()));

        assertEquals(200, response.getStatus());
        assertThat(registry).hasNumberOfObservationsEqualTo(1)
                .hasSingleObservationThat()
                .hasNameEqualTo("paztport.request")
                .hasLowCardinalityKeyValue("mode", "enforce")
                .hasLowCardinalityKeyValue("reason", "OK")
                .hasLowCardinalityKeyValue("outcome", "served")
                .doesNotHaveError()
                .hasBeenStopped();
    }

    @Test
    void enforceRecordsTheRefusalsCode() throws Exception {
        MockHttpServletResponse response = run(filter(VerificationMode.ENFORCE, null),
                paymentRequest(new Headers(null, null, null)));

        assertEquals(403, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "enforce")
                .hasLowCardinalityKeyValue("reason", "CHAIN_MISSING")
                .hasLowCardinalityKeyValue("outcome", "refused")
                .hasBeenStopped();
    }

    @Test
    void auditRecordsAFailureAsServed() throws Exception {
        MockHttpServletResponse response = run(filter(VerificationMode.AUDIT, null),
                paymentRequest(new Headers(null, null, null)));

        assertEquals(200, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "audit")
                .hasLowCardinalityKeyValue("reason", "CHAIN_MISSING")
                .hasLowCardinalityKeyValue("outcome", "served")
                .hasBeenStopped();
    }

    // Audit still refuses influence it cannot read, so its outcome is the refusal's, not the result's.
    @Test
    void auditRecordsUnreadableInfluenceAsRefused() throws Exception {
        Headers h = validHeaders();

        MockHttpServletResponse response = run(filter(VerificationMode.AUDIT, null),
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%")));

        assertEquals(400, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "audit")
                .hasLowCardinalityKeyValue("reason", "INFLUENCE_MISMATCH")
                .hasLowCardinalityKeyValue("outcome", "refused")
                .hasBeenStopped();
    }

    @Test
    void offRecordsNoReason() throws Exception {
        MockHttpServletResponse response = run(filter(VerificationMode.OFF, null), paymentRequest(validHeaders()));

        assertEquals(200, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "off")
                .hasLowCardinalityKeyValue("reason", "none")
                .hasLowCardinalityKeyValue("outcome", "served");
    }

    @Test
    void offRecordsUnreadableInfluenceAsRefusedWithNoReason() throws Exception {
        Headers h = validHeaders();

        MockHttpServletResponse response = run(filter(VerificationMode.OFF, null),
                paymentRequest(new Headers(h.chain(), h.proof(), "%%%")));

        assertEquals(400, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "off")
                .hasLowCardinalityKeyValue("reason", "none")
                .hasLowCardinalityKeyValue("outcome", "refused");
    }

    // A hop that does not verify requests still checks the chain to decide whether it attests.
    @Test
    void aHopWithNoModeRecordsAttestationsCheck() throws Exception {
        run(attestingFilter(false), paymentRequest(validHeaders()));

        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "none")
                .hasLowCardinalityKeyValue("reason", "OK")
                .hasLowCardinalityKeyValue("outcome", "served");
    }

    @Test
    void theControlPlaneIsNotObserved() throws Exception {
        MockHttpServletRequest scrape = new MockHttpServletRequest("GET", "/actuator/prometheus");

        run(filter(VerificationMode.ENFORCE, null), scrape);

        assertThat(registry).doesNotHaveAnyObservation();
    }

    // A chain and an influence entry carrying text of their own must not reach a tag.
    @Test
    void onlyFixedTagsAreRecorded() throws Exception {
        InfluenceEntry hostile = new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:hostile-source", "hostile-hash",
                null, "hostile-owner");
        MockHttpServletRequest request = paymentRequest(headers("hostile rid {x=1}", List.of(hostile)));
        request.addHeader("X-Forwarded-For", "hostile-peer");

        run(filter(VerificationMode.ENFORCE, null), request);

        assertThat(registry).hasSingleObservationThat()
                .hasOnlyKeys("mode", "reason", "outcome")
                .hasLowCardinalityKeyValue("reason", "OK");
        Set<String> allowed = Stream.concat(FIXED.stream(), Stream.of(ReasonCode.values()).map(Enum::name))
                .collect(Collectors.toSet());
        assertThat(registry).hasHandledContextsThatSatisfy(contexts -> {
            assertEquals(1, contexts.size());
            Observation.Context context = contexts.get(0);
            List<String> values = context.getLowCardinalityKeyValues().stream().map(KeyValue::getValue).toList();
            assertTrue(allowed.containsAll(values), values.toString());
            assertEquals(0, context.getHighCardinalityKeyValues().stream().count());
        });
    }

    // The handler of an attested answer runs after the filter has decided, so the decision is already recorded.
    @Test
    void theObservationEndsBeforeTheHandler() throws Exception {
        List<Boolean> stoppedWhenHandled = new ArrayList<>();
        HttpServlet handler = new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse res) {
                assertThat(registry).hasSingleObservationThat().hasBeenStopped();
                stoppedWhenHandled.add(true);
            }
        };
        MockHttpServletResponse response = new MockHttpServletResponse();

        attestingFilter(true).doFilter(paymentRequest(validHeaders()), response, new MockFilterChain(handler));

        assertEquals(List.of(true), stoppedWhenHandled, "the handler ran");
        assertThat(registry).hasSingleObservationThat().hasLowCardinalityKeyValue("reason", "OK").hasBeenStopped();
    }

    @Test
    void aThrowingDecisionStopsWithTheError() throws Exception {
        IllegalStateException failure = new IllegalStateException("listener failed");
        ReceivedRequestListener throwing = (chain, proof, influence, method, target, body) -> {
            throw failure;
        };

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> run(filter(VerificationMode.ENFORCE, throwing), paymentRequest(validHeaders())));

        assertSame(failure, thrown);
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("mode", "enforce")
                .hasLowCardinalityKeyValue("reason", "none")
                .hasLowCardinalityKeyValue("outcome", "refused")
                .hasError(failure)
                .hasBeenStopped();
    }

    // The request's scope holds the chain verified here: a handler that throws must not leave it on a pooled thread.
    @Test
    void aHandlerThatThrowsOnStopLeavesNoScopeOpen() {
        IllegalStateException failure = new IllegalStateException("handler failed");
        InboundFilter filter = new InboundFilter(paymentVerifier(), true, false, "payment",
                new ModeHolder(VerificationMode.ENFORCE), event -> { }, null, null, throwingOnStop(failure));

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> run(filter, paymentRequest(validHeaders())));

        assertSame(failure, thrown);
        assertFalse(RequestContext.isOpen());
        assertNull(RequestContext.verifiedChain());
    }

    // A handler that throws as the observation stops must not hide why the decision failed.
    @Test
    void aThrowingDecisionKeepsItsExceptionWhenAHandlerThrowsOnStop() {
        IllegalStateException failure = new IllegalStateException("listener failed");
        IllegalStateException stopping = new IllegalStateException("handler failed");
        ReceivedRequestListener listener = (chain, proof, influence, method, target, body) -> {
            throw failure;
        };
        InboundFilter filter = new InboundFilter(paymentVerifier(), true, false, "payment",
                new ModeHolder(VerificationMode.ENFORCE), event -> { }, listener, null, throwingOnStop(stopping));

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> run(filter, paymentRequest(validHeaders())));

        assertSame(failure, thrown);
        assertArrayEquals(new Throwable[] {stopping}, thrown.getSuppressed());
        assertFalse(RequestContext.isOpen());
        assertNull(RequestContext.verifiedChain());
    }

    // The partner's observations ------------------------------------------------------------------------------

    @Test
    void anAttestedCallRecordsOkAndServed() throws Exception {
        MockHttpServletResponse response = serve(charge(handshake(true), CHARGE));

        assertEquals(200, response.getStatus());
        assertThat(registry).hasNumberOfObservationsEqualTo(1)
                .hasSingleObservationThat()
                .hasNameEqualTo("paztport.partner.request")
                .hasOnlyKeys("session", "reason", "outcome")
                .hasLowCardinalityKeyValue("session", "attested")
                .hasLowCardinalityKeyValue("reason", "OK")
                .hasLowCardinalityKeyValue("outcome", "served")
                .doesNotHaveError()
                .hasBeenStopped();
    }

    @Test
    void aFailingCallInAnAttestedSessionRecordsItsCodeAndRefused() throws Exception {
        MockHttpServletResponse response = serve(charge(handshake(true),
                "{\"amount\":999}".getBytes(StandardCharsets.UTF_8)));

        assertEquals(403, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("session", "attested")
                .hasLowCardinalityKeyValue("reason", "BINDING_MISMATCH")
                .hasLowCardinalityKeyValue("outcome", "refused")
                .hasBeenStopped();
    }

    @Test
    void anUnknownSessionRecordsUnknownAndRefused() throws Exception {
        MockHttpServletResponse response = serve(charge("no-such-session", CHARGE));

        assertEquals(403, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("session", "unknown")
                .hasLowCardinalityKeyValue("reason", "none")
                .hasLowCardinalityKeyValue("outcome", "refused")
                .hasBeenStopped();
    }

    @Test
    void anUnsafeSessionRecordsNoReasonAndServed() throws Exception {
        MockHttpServletResponse response = serve(charge(handshake(false), CHARGE));

        assertEquals(200, response.getStatus());
        assertThat(registry).hasSingleObservationThat()
                .hasLowCardinalityKeyValue("session", "unsafe")
                .hasLowCardinalityKeyValue("reason", "none")
                .hasLowCardinalityKeyValue("outcome", "served")
                .hasBeenStopped();
    }

    // An attested call's scope holds its verified chain and influence, which must not outlive it either.
    @Test
    void aHandlerThatThrowsOnStopLeavesNoPartnerScopeOpen() throws Exception {
        IllegalStateException failure = new IllegalStateException("handler failed");
        PartnerFilter filter = new PartnerFilter(sessions, "psp", throwingOnStop(failure));
        MockHttpServletRequest call = charge(handshake(true), CHARGE);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> filter.doFilter(call, new MockHttpServletResponse(), new MockFilterChain()));

        assertSame(failure, thrown);
        assertFalse(RequestContext.isOpen());
        assertNull(RequestContext.verifiedChain());
    }

    // Once the call is decided its scope is open: a handler that throws as the observation's scope closes must still
    // leave it ended, and one that then throws as the observation stops must not hide the first exception.
    @Test
    void aFailingScopeCloseKeepsItsExceptionWhenAHandlerThrowsOnStop() throws Exception {
        IllegalStateException closing = new IllegalStateException("handler failed as the scope closed");
        IllegalStateException stopping = new IllegalStateException("handler failed as it stopped");
        ObservationRegistry throwing = throwing(closing, stopping);
        PartnerFilter filter = new PartnerFilter(sessions, "psp", throwing);
        MockHttpServletRequest call = charge(handshake(true), CHARGE);
        try {
            IllegalStateException thrown = assertThrows(IllegalStateException.class,
                    () -> filter.doFilter(call, new MockHttpServletResponse(), new MockFilterChain()));

            assertSame(closing, thrown);
            assertArrayEquals(new Throwable[] {stopping}, thrown.getSuppressed());
            assertFalse(RequestContext.isOpen());
            assertNull(RequestContext.verifiedChain());
        } finally {
            // Micrometer restores the thread's current observation only after its handlers are told the scope closed.
            throwing.setCurrentObservationScope(null);
        }
    }

    @Test
    void thePartnersControlPlaneAndHandshakeAreNotObserved() throws Exception {
        for (String path : List.of("/actuator/prometheus", HttpSessions.PATH)) {
            serve(new MockHttpServletRequest("GET", path));
        }

        assertThat(registry).doesNotHaveAnyObservation();
    }
}
