// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;

/** The stamper's output, checked by the live verifier it feeds: calls, the blocks they commit to, and responses. */
class StamperTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final long NOW = 1_000_000L;
    private static final String RID = "rid-1";
    private static final Block NOTED = Block.of(Map.of("example", List.of("{\"note\":\"n1\"}", "7")), List.of());

    private final KeyPair gatewayKey = Crypto.generateEd25519KeyPair();
    private final KeyPair ordersKey = Crypto.generateEd25519KeyPair();
    private final KeyPair paymentKey = Crypto.generateEd25519KeyPair();
    private final KeyPair policyKey = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result policy = PolicyBuilder.build(
            List.of(List.of("gateway", "orders", "payment")), 4, NOT_AFTER, policyKey.getPrivate());

    private Stamper stamper(String svc, KeyPair key, boolean origin) {
        return new Stamper(svc, svc + "-1", key.getPrivate(), origin, () -> RID, () -> NOW);
    }

    private Verifier verifier() {
        long notAfter = policy.signedRoot().notAfter();
        return new Verifier(new VerifierConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gatewayKey.getPublic(), "orders",
                        ordersKey.getPublic(), "payment", paymentKey.getPublic())), notAfter)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), notAfter)),
                notAfter, Set.of("gateway"), "",
                new InMemoryNonceCache(60_000), () -> NOW, 30_000, 300_000, ExtensionSettings.NONE));
    }

    private static String json(List<Stamp> chain) {
        return Chains.toJson(chain);
    }

    private static String json(MerkleProof proof) {
        return proof == null ? null : proof.toJson();
    }

    private Stamper.Stamped toOrders(String bind, Block block) {
        return stamper("gateway", gatewayKey, true).next(List.of(), "orders", bind, block,
                policy.bundles().get("gateway"));
    }

    private Stamper.Stamped toPayment(Stamper.Stamped fromGateway, Block block) {
        return stamper("orders", ordersKey, false).next(fromGateway.chain(), "payment", "b2", block,
                policy.bundles().get("orders"));
    }

    private Stamper.Stamped toPayment(Stamper.Stamped fromGateway) {
        return toPayment(fromGateway, Block.EMPTY);
    }

    /**
     * Why a service must verify a chain before it attests a response to it. A response stamp is shaped like a
     * request stamp, and {@link Stamper#respond} checks nothing: on a forged one-stamp chain with an empty
     * {@code sig} (which parses, since {@code ""} is canonical base64url), the origin's response has {@code prev}
     * {@code ""} and so is a valid origin stamp, addressed to whichever service the forgery named. That service, once
     * handed it as a chain, appends its own stamp, and the receiver after it accepts a request tree the origin never
     * started. The Spring filter therefore attests only a chain it verified, and an origin never attests.
     */
    @Test
    void aResponseToAnUncheckedChainIsAValidOriginStamp() {
        List<Stamp> forged = List.of(new Stamp("orders", "x", RID, NOW, "", "x", "b", "", "", ""));

        Stamp minted = stamper("gateway", gatewayKey, true).respond(forged, "h", RID, Block.EMPTY);
        Stamper.Stamped driven = stamper("orders", ordersKey, false).next(List.of(minted), "payment", "b2",
                Block.EMPTY, policy.bundles().get("orders"));

        VerifyResult r = verifier().verify(new VerifyInput(json(driven.chain()), "b2",
                null, json(driven.proof()), "payment", true, RID + "|orders|req",
                new Peer("orders", "10.0.0.3")));
        assertEquals(ReasonCode.OK, r.reason(), "the attack the filter's rule closes");
    }

    private static final String SESS = "sess-1";

    private final PolicyBuilder.Result egress = PolicyBuilder.build(
            List.of(List.of("payment", "psp")), 4, NOT_AFTER, policyKey.getPrivate());

    private Stamper.Stamped boundary(String sess, ProofBundle bundle) {
        Stamp inbound = toPayment(toOrders("b1", Block.EMPTY)).chain().get(1);
        return stamper("payment", paymentKey, false).boundary(List.of(inbound), sess, "psp", "b3", NOTED, bundle);
    }

    @Test
    void boundaryStampFields() {
        Stamper.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(1, b.chain().size());
        Stamp s = b.chain().get(0);
        assertEquals("payment", s.svc());
        assertEquals("payment-1", s.inst());
        assertEquals(RID, s.rid());
        assertEquals(NOW, s.ts());
        assertEquals(SESS, s.sess());
        assertEquals("psp", s.rcv());
        assertEquals("b3", s.bind());
        assertEquals(NOTED.commit(), s.ext());
        assertEquals("", s.prev());
    }

    @Test
    void boundaryProofForEgressRoute() {
        Stamper.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(egress.signedRoot().rootId(), b.proof().rootId());
        assertNull(boundary(SESS, policy.bundles().get("payment")).proof());
    }

    @Test
    void boundaryRefusesEmptySess() {
        assertThrows(IllegalArgumentException.class, () -> boundary("", egress.bundles().get("payment")));
        assertThrows(IllegalArgumentException.class, () -> boundary(null, egress.bundles().get("payment")));
    }

    @Test
    void boundaryRefusesNoChain() {
        Stamper payment = stamper("payment", paymentKey, false);
        assertThrows(IllegalStateException.class,
                () -> payment.boundary(null, SESS, "psp", "b3", Block.EMPTY, null));
        assertThrows(IllegalStateException.class,
                () -> payment.boundary(List.of(), SESS, "psp", "b3", Block.EMPTY, null));
    }

    private VerifyResult verifyAtPartner(Stamper.Stamped b, String sess) {
        String pin = Base64Url.encode(Crypto.encodePublicKey(policyKey.getPublic()));
        KeyringFile ring = KeyringFile.sign(Map.of("payment", Base64Url.encode(Crypto.encodePublicKey(
                paymentKey.getPublic()))), pin, NOT_AFTER, policyKey.getPrivate());
        Verifier partner = new Verifier(VerifierConfig.pinned(List.of(ring), List.of(egress.signedRoot()), pin,
                NOW, Set.of("payment"), sess, new InMemoryNonceCache(60_000), () -> NOW, 30_000, 300_000,
                ExtensionSettings.NONE));
        return partner.verify(new VerifyInput(json(b.chain()), "b3", Block.toJson(List.of(NOTED)),
                json(b.proof()), "psp", true, RID + "|payment|req", new Peer("payment", "10.0.0.1")));
    }

    @Test
    void boundaryVerifiesAsPartner() {
        Stamper.Stamped b = boundary(SESS, egress.bundles().get("payment"));
        assertEquals(ReasonCode.OK, verifyAtPartner(b, SESS).reason());
        assertEquals(ReasonCode.SESSION_UNKNOWN, verifyAtPartner(b, "").reason());
    }

    @Test
    void hopsVerify() {
        Stamper.Stamped first = toOrders("b1", Block.EMPTY);
        assertNull(first.proof());
        Stamper.Stamped second = toPayment(first);
        assertEquals(2, second.chain().size());
        VerifyResult r = verifier().verify(new VerifyInput(json(second.chain()), "b2",
                null, json(second.proof()), "payment", true,
                RID + "|orders|req", null));
        assertEquals(ReasonCode.OK, r.reason());
    }

    @Test
    void theStampCommitsToItsBlock() {
        Stamper.Stamped second = toPayment(toOrders("b1", Block.EMPTY), NOTED);
        assertEquals(NOTED.commit(), second.chain().get(1).ext());
        assertEquals("", second.chain().get(0).ext());
        assertEquals(ReasonCode.OK, verifier().verify(new VerifyInput(json(second.chain()), "b2",
                Block.toJson(List.of(Block.EMPTY, NOTED)), json(second.proof()), "payment", true, RID + "|orders|a",
                null)).reason());
        assertEquals(ReasonCode.EXTENSION_MISMATCH, verifier().verify(new VerifyInput(json(second.chain()), "b2",
                null, json(second.proof()), "payment", true, RID + "|orders|b", null)).reason());
    }

    @Test
    void theBoundaryStampCommitsToItsBlock() {
        assertEquals(NOTED.commit(), boundary(SESS, null).chain().get(0).ext());
        Stamp inbound = toPayment(toOrders("b1", Block.EMPTY)).chain().get(1);
        assertEquals("", stamper("payment", paymentKey, false)
                .boundary(List.of(inbound), SESS, "psp", "b3", Block.EMPTY, null).chain().get(0).ext());
    }

    @Test
    void theResponseStampCommitsToItsBlock() {
        List<Stamp> sent = toPayment(toOrders("b1", Block.EMPTY)).chain();
        Stamper payment = stamper("payment", paymentKey, false);
        assertEquals(NOTED.commit(), payment.respond(sent, "hash-1", RID, NOTED).ext());
        assertEquals("", payment.respond(sent, "hash-1", RID, Block.EMPTY).ext());
    }

    /** A null block is a caller's fault, refused before the clock is read or a key used, so nothing is signed. */
    @Test
    void aNullBlockIsRefusedBeforeAnythingIsSigned() {
        boolean[] read = {false};
        Stamper orders = new Stamper("orders", "orders-1", ordersKey.getPrivate(), false, () -> RID, () -> {
            read[0] = true;
            return NOW;
        });
        List<Stamp> inbound = toOrders("b1", Block.EMPTY).chain();
        assertThrows(NullPointerException.class, () -> orders.next(inbound, "payment", "b2", null, null));
        assertThrows(NullPointerException.class, () -> orders.boundary(inbound, SESS, "psp", "b3", null, null));
        assertThrows(NullPointerException.class, () -> orders.respond(inbound, "h", RID, null));
        assertFalse(read[0], "the clock was not read, so no stamp was made");
    }

    /** J11: the stamper commits to a block and reads no extension. */
    @Test
    void theStamperImportsNoExtension() throws IOException {
        Path source = Path.of("src/main/java/org/paztport/core/stamp/Stamper.java");
        assertTrue(Files.isRegularFile(source), source.toAbsolutePath().toString());
        assertFalse(Files.readString(source).contains("org.paztport.core.influence"));
    }

    /** payment answers orders; the chain and proof orders sent are what the caller verifies against. */
    private record Response(List<Stamp> sent, MerkleProof proof, Stamp stamp) {
        String chain() {
            List<Stamp> all = new ArrayList<>(sent);
            all.add(stamp);
            return Chains.toJson(all);
        }
    }

    private Response response() {
        Stamper.Stamped second = toPayment(toOrders("b1", Block.EMPTY));
        Stamp stamp = stamper("payment", paymentKey, false).respond(second.chain(), "hash-1", RID, Block.EMPTY);
        return new Response(second.chain(), second.proof(), stamp);
    }

    private VerifyResult verifyResponse(Response r, String bind, String receiver) {
        return verifier().verify(new VerifyInput(r.chain(), bind, null,
                json(r.proof()), receiver, false, RID + "|payment|resp", null));
    }

    @Test
    void responseVerifies() {
        Response r = response();
        assertEquals("orders", r.stamp().rcv());
        assertEquals("", r.stamp().ext());
        assertEquals(ReasonCode.OK, verifyResponse(r, Bindings.response("hash-1", RID), "orders").reason());
    }

    @Test
    void responseToAnotherResultIsBindingMismatch() {
        Response r = response();
        assertEquals(ReasonCode.BINDING_MISMATCH,
                verifyResponse(r, Bindings.response("hash-2", RID), "orders").reason());
    }

    @Test
    void responseToWrongCaller() {
        Response r = response();
        assertEquals(ReasonCode.BINDING_MISMATCH,
                verifyResponse(r, Bindings.response("hash-1", RID), "gateway").reason());
    }

    @Test
    void nonOriginNeedsChain() {
        Stamper orders = stamper("orders", ordersKey, false);
        assertThrows(IllegalStateException.class, () -> orders.next(List.of(), "payment", "b", Block.EMPTY, null));
        assertThrows(IllegalStateException.class, () -> orders.respond(List.of(), "h", RID, Block.EMPTY));
    }

    // --- Refusing what could never verify: nothing is signed for a name no policy can hold ---

    private static final List<String> BAD_NODES = Arrays.asList(null, "", ".", "..", "a/b", "a\\b", "a|b");

    @Test
    void nextRefusesAReceiverThatIsNotARouteNode() {
        Stamper gateway = stamper("gateway", gatewayKey, true);
        for (String bad : BAD_NODES) {
            assertThrows(IllegalArgumentException.class, () -> gateway.next(null, bad, "b1", Block.EMPTY, null),
                    String.valueOf(bad));
        }
    }

    @Test
    void everySigningPathRefusesASvcThatIsNotARouteNode() {
        List<Stamp> inbound = stamper("gateway", gatewayKey, true).next(null, "orders", "b1", Block.EMPTY, null)
                .chain();
        for (String bad : BAD_NODES) {
            Stamper s = new Stamper(bad, "i", ordersKey.getPrivate(), false, () -> RID, () -> NOW);
            assertThrows(IllegalArgumentException.class, () -> s.next(inbound, "payment", "b2", Block.EMPTY, null),
                    "next " + bad);
            assertThrows(IllegalArgumentException.class,
                    () -> s.boundary(inbound, SESS, "psp", "b3", Block.EMPTY, null), "boundary " + bad);
            assertThrows(IllegalArgumentException.class, () -> s.respond(inbound, "h", "c", Block.EMPTY),
                    "respond " + bad);
        }
    }

    @Test
    void boundaryRefusesAPartnerEntryThatIsNotARouteNode() {
        Stamper payment = stamper("payment", paymentKey, false);
        List<Stamp> inbound = stamper("gateway", gatewayKey, true).next(null, "payment", "b1", Block.EMPTY, null)
                .chain();
        for (String bad : BAD_NODES) {
            assertThrows(IllegalArgumentException.class,
                    () -> payment.boundary(inbound, SESS, bad, "b3", Block.EMPTY, null), String.valueOf(bad));
        }
    }

    @Test
    void respondRefusesACallerThatIsNotARouteNode() {
        // An unverified chain whose last svc is empty: the response would name an empty receiver.
        Stamp odd = Stamp.sign("", "i", RID, NOW, "", "orders", "b1", "", "", gatewayKey.getPrivate());
        Stamper orders = stamper("orders", ordersKey, false);
        assertThrows(IllegalArgumentException.class, () -> orders.respond(List.of(odd), "h", "c", Block.EMPTY));
    }

    @Test
    void aStampOverAnEmptyRcvStillReadsAndSignsAtTheLowLevel() {
        // The route-node rule is the stamper's; Stamp itself is what verifiers rebuild signing bytes with.
        Stamp s = Stamp.sign("gateway", "i", RID, NOW, "", "", "b1", "", "", gatewayKey.getPrivate());
        assertEquals("", s.rcv());
    }

    /** The proof of {@code route}, from whichever bundle of a policy over it holds it, in a bundle of its own. */
    private ProofBundle bundleFor(String... route) {
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of(route)), 4, NOT_AFTER,
                policyKey.getPrivate());
        String key = String.join("/", route);
        MerkleProof proof = built.bundles().values().stream().map(b -> b.proofFor(key))
                .filter(p -> p != null).findFirst().orElseThrow();
        return new ProofBundle("orders", built.signedRoot().rootId(), Map.of(key, proof));
    }

    @Test
    void nextLooksUpTheRouteFromRcv() {
        ProofBundle bundle = bundleFor("gateway", "orders#createOrder", "payment#charge");
        Stamper.Stamped fromGateway = stamper("gateway", gatewayKey, true).next(List.of(), "orders#createOrder", "b",
                Block.EMPTY, null);
        Stamper.Stamped toPayment = stamper("orders", ordersKey, false).next(fromGateway.chain(), "payment#charge",
                "b2", Block.EMPTY, bundle);
        assertEquals(bundle.proofFor("gateway/orders#createOrder/payment#charge"), toPayment.proof());
    }

    @Test
    void refusesAServiceNameWithHash() {
        Stamper bad = stamper("a#b", ordersKey, true);
        assertThrows(IllegalArgumentException.class, () -> bad.next(List.of(), "payment", "b", Block.EMPTY, null));
    }

    @Test
    void refusesAnEmptyOperation() {
        Stamper gateway = stamper("gateway", gatewayKey, true);
        assertThrows(IllegalArgumentException.class,
                () -> gateway.next(List.of(), "payment#", "b", Block.EMPTY, null));
    }
}
