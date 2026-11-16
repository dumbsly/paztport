// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.Accepted;
import org.paztport.http.HttpReceiver;
import org.paztport.http.InboundRequest;
import org.paztport.http.VerificationMode;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

// Payment's side of rows 4, 4b and 8c, over a real receiver and verifier set up as payment's are: it verifies, acts on
// influence, and trusts the routes the demo's policy holds, none of which goes from search to payment. A gateway
// that acts on influence commits its stamp to a block that is not the empty one, so a chain search stole reaches the
// route check only with the blocks it came with; without them, or with one altered, check 9a refuses it first.
class StolenChainBlocksTest {

    /** The validity window of the fixture root and keyring: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;
    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    private final KeyPair gatewayKeys = Crypto.generateEd25519KeyPair();
    private final KeyPair searchKeys = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(List.of(
            List.of("gateway", "orders#createOrder", "payment#pay"), List.of("gateway", "orders#createOrder"),
            List.of("gateway", "search")), 4, NOT_AFTER, Crypto.generateEd25519KeyPair().getPrivate());
    /** The gateway acts on influence, so its block names it with nothing added. */
    private final Block gatewayBlock = Influence.block(List.of(), List.of());
    private final List<AttestationEvent> events = new ArrayList<>();
    private final HttpReceiver payment = HttpReceiver.builder("payment").verifier(verifier()).verifyRequests(true)
            .publisher(events::add).build();

    private Verifier verifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gatewayKeys.getPublic(), "search",
                        searchKeys.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "", new InMemoryNonceCache(), System::currentTimeMillis, 5000, 5000,
                ExtensionSettings.of(Set.of(Influence.NAME), null)));
    }

    /** A chain the gateway sent search, stolen, and search's stamp for payment's pay after it, as row 4 sends. */
    private Map<String, String> stolenAndForwarded() {
        String rid = UUID.randomUUID().toString();
        Stamper.Stamped toSearch = new Stamper("gateway", "gateway-1", gatewayKeys.getPrivate(), true, () -> rid,
                System::currentTimeMillis)
                .next(null, "search", RequestBinding.compute("GET", "/search", new byte[0]), gatewayBlock,
                        policy.bundles().get("gateway"));
        // Search acts on no extension, so its own block is the empty one; no proof proves its route to payment.
        Stamper.Stamped toPayment = new Stamper("search", "search-1", searchKeys.getPrivate(), false, () -> "unused",
                System::currentTimeMillis)
                .next(toSearch.chain(), "payment#pay", RequestBinding.compute("POST", "/pay", BODY), Block.EMPTY,
                        policy.bundles().get("search"));
        Map<String, String> headers = new HashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(toPayment.chain()));
        if (toPayment.proof() != null) {
            headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(toPayment.proof()));
        }
        headers.put(PaztportHeaders.EXTENSIONS, HttpWire.encodeBlocks(List.of(gatewayBlock, Block.EMPTY)));
        return headers;
    }

    /** Payment's decision on {@code headers} under {@code enforce}, as {@link #fromSearch(Map, VerificationMode)}. */
    private Accepted fromSearch(Map<String, String> headers) {
        return fromSearch(headers, VerificationMode.ENFORCE);
    }

    /** Payment's decision on {@code headers} in {@code mode}, sent from search over mutual TLS to pay's handler. */
    private Accepted fromSearch(Map<String, String> headers, VerificationMode mode) {
        return payment.accept(new InboundRequest("POST", "/pay", headers, BODY, "pay"), new Peer("search", "search-1"),
                mode);
    }

    private void assertRefused(Accepted accepted, String reason) {
        assertNotNull(accepted.refusal(), "refused");
        assertEquals(403, accepted.refusal().status());
        assertEquals("{\"reason\":\"" + reason + "\"}", new String(accepted.refusal().json(), StandardCharsets.UTF_8));
        AttestationEvent event = events.get(events.size() - 1);
        assertEquals(reason, event.reason());
        assertEquals("search", event.suspectSvc(), "the peer the transport authenticated is named");
    }

    @Test
    void withTheBlocksItCameWithTheStolenChainReachesTheRouteCheck() {
        assertRefused(fromSearch(stolenAndForwarded()), "PATH_NOT_ALLOWED");
    }

    @Test
    void withoutItsBlocksItIsAnExtensionMismatch() {
        Map<String, String> headers = stolenAndForwarded();
        headers.remove(PaztportHeaders.EXTENSIONS);

        assertRefused(fromSearch(headers), "EXTENSION_MISMATCH");
    }

    @Test
    void withOneBlockAlteredItIsAnExtensionMismatch() {
        Map<String, String> headers = stolenAndForwarded();
        InfluenceEntry added = new InfluenceEntry(InfluenceClass.PUBLIC, "search:attack", "h", null, null);
        headers.put(PaztportHeaders.EXTENSIONS,
                HttpWire.encodeBlocks(List.of(Influence.block(List.of(added), List.of()), Block.EMPTY)));

        assertRefused(fromSearch(headers), "EXTENSION_MISMATCH");
    }

    // Row 8c: under audit the stolen chain with its blocks fails the route check and is served, unverified, with an
    // audit event; without them it is not served even under audit, since no hop serves a request whose blocks fail
    // check 9a (verification.md, Modes and refusals).
    @Test
    void underAuditTheStolenChainIsServedOnlyWithItsBlocks() {
        Accepted served = fromSearch(stolenAndForwarded(), VerificationMode.AUDIT);
        assertNull(served.refusal(), "served");
        assertNull(served.verifiedChain(), "and not verified");
        AttestationEvent event = events.get(events.size() - 1);
        assertEquals("PATH_NOT_ALLOWED", event.reason());
        assertTrue(event.audit(), "the event says it was audit's");

        Map<String, String> headers = stolenAndForwarded();
        headers.remove(PaztportHeaders.EXTENSIONS);
        Accepted refused = fromSearch(headers, VerificationMode.AUDIT);
        assertNotNull(refused.refusal(), "refused");
        assertEquals(400, refused.refusal().status());
        assertEquals("{\"reason\":\"EXTENSION_MISMATCH\"}",
                new String(refused.refusal().json(), StandardCharsets.UTF_8));
    }
}
