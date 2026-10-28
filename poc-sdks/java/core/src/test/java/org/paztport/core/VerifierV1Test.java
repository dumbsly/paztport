// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class VerifierV1Test {

    private final Fixture fx = new Fixture();

    @Test
    void validScenarioOnePasses() {
        VerifyResult r = fx.verifier().verify(fx.validRequest());
        assertTrue(r.ok(), "expected OK, got " + r.reason());
        assertEquals(ReasonCode.OK, r.reason());
    }

    @Test
    void missingChainHeaderIsChainMissing() {
        VerifyRequestV1 req = new VerifyRequestV1(null, fx.validProofHeader(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.CHAIN_MISSING, fx.verifier().verify(req).reason());
    }

    @Test
    void emptyChainIsChainMissing() {
        String empty = new PathChainV1(List.of()).encode();
        VerifyRequestV1 req = new VerifyRequestV1(empty, fx.validProofHeader(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.CHAIN_MISSING, fx.verifier().verify(req).reason());
    }

    @Test
    void unparseableChainIsChainMissing() {
        VerifyRequestV1 req = new VerifyRequestV1("!!!garbage!!!", fx.validProofHeader(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.CHAIN_MISSING, fx.verifier().verify(req).reason());
    }

    @Test
    void nonOriginFirstStampIsBadOrigin() {
        // search is a known service with a valid key, but is not an allowed origin.
        StampV1 s = StampSignerV1.sign("search", "s-1", "rid-1", Fixture.NOW, "b", "", fx.search.getPrivate());
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(s)));
        assertEquals(ReasonCode.BAD_ORIGIN, fx.verifier().verify(req).reason());
    }

    @Test
    void stampClaimingGatewaySignedByAnotherKeyIsBadSignature() {
        // Scenario 3: search forges a stamp claiming svc gateway with its own key.
        StampV1 forged = StampSignerV1.sign("gateway", "evil", "rid-1", Fixture.NOW, fx.bindToPayment(), "", fx.search.getPrivate());
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(forged)));
        assertEquals(ReasonCode.BAD_SIGNATURE, fx.verifier().verify(req).reason());
    }

    @Test
    void prevNotMatchingPreviousSignatureIsBrokenLink() {
        StampV1 s0 = fx.gatewayStamp();
        // Validly signed, but prev points at something other than s0's signature.
        StampV1 s1 = StampSignerV1.sign("orders", "ord-1", "rid-1", Fixture.NOW, fx.bindToPayment(),
                Base64Url.encode("not-s0-sig".getBytes()), fx.orders.getPrivate());
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(s0, s1)));
        assertEquals(ReasonCode.BROKEN_LINK, fx.verifier().verify(req).reason());
    }

    @Test
    void stampOlderThanMaxAgeIsExpired() {
        StampV1 s0 = StampSignerV1.sign("gateway", "gw-1", "rid-1", Fixture.NOW - 6000, "bGW", "", fx.gateway.getPrivate());
        StampV1 s1 = StampSignerV1.sign("orders", "ord-1", "rid-1", Fixture.NOW - 6000, fx.bindToPayment(), s0.sig(), fx.orders.getPrivate());
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(s0, s1)));
        assertEquals(ReasonCode.EXPIRED, fx.verifier().verify(req).reason());
    }

    @Test
    void stampsWithDifferentRidsAreRidMismatch() {
        StampV1 s0 = fx.gatewayStamp();
        StampV1 s1 = StampSignerV1.sign("orders", "ord-1", "rid-DIFFERENT", Fixture.NOW, fx.bindToPayment(), s0.sig(), fx.orders.getPrivate());
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(s0, s1)));
        assertEquals(ReasonCode.RID_MISMATCH, fx.verifier().verify(req).reason());
    }

    @Test
    void bodyAlteredAfterLastStampIsBindingMismatch() {
        // Scenario 6: valid chain, but payment receives a different body.
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), fx.validProofHeader(), fx.bindToPayment() + "-altered", "payment");
        assertEquals(ReasonCode.BINDING_MISMATCH, fx.verifier().verify(req).reason());
    }

    @Test
    void replayingTheSameRequestIsReplay() {
        // Scenario 5: first call passes, the verbatim replay is caught.
        VerifierV1 verifier = fx.verifier();
        assertTrue(verifier.verify(fx.validRequest()).ok());
        assertEquals(ReasonCode.REPLAY, verifier.verify(fx.validRequest()).reason());
    }

    @Test
    void gatewaySearchChainForwardedToPaymentIsPathNotAllowed() {
        // Scenario 4: a real gateway->search chain forwarded on to payment, carrying
        // the only proof search holds (for gateway/search). No leaf to payment exists.
        VerifyRequestV1 req = new VerifyRequestV1(
                fx.gatewaySearchChainHeader(), fx.proofHeaderFor("gateway/search"), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    @Test
    void missingProofIsPathNotAllowed() {
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), null, fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    @Test
    void proofForWrongRootVersionIsPathNotAllowed() {
        // A proof whose rootId does not match the pinned root is rejected.
        MerkleProof valid = fx.tree.proofFor("gateway/orders/payment");
        MerkleProof wrongVersion = new MerkleProof(valid.leafSalt(), valid.siblings(), valid.dirs(), "v-OLD");
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), wrongVersion.encode(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    private static void assertNoSuspect(VerifyResult r, ReasonCode expected) {
        assertEquals(expected, r.reason());
        assertEquals("", r.suspectSvc(), expected + " must not name a service");
        assertEquals("", r.suspectInst(), expected + " must not name an instance");
    }

    @Test
    void onlyPathNotAllowedAndOkNameTheLastStamp() {
        // OK and PATH_NOT_ALLOWED: signed, linked, fresh, bound and unseen, so the last hop sent it.
        VerifyResult ok = fx.verifier().verify(fx.validRequest());
        assertEquals("orders", ok.suspectSvc());
        assertEquals("ord-1", ok.suspectInst());
        VerifyResult notAllowed = fx.verifier().verify(
                new VerifyRequestV1(fx.validChainHeader(), null, fx.bindToPayment(), "payment"));
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, notAllowed.reason());
        assertEquals("orders", notAllowed.suspectSvc());
        assertEquals("ord-1", notAllowed.suspectInst());

        // Unsigned or unverified names stay empty.
        assertNoSuspect(fx.verifier().verify(new VerifyRequestV1(null, fx.validProofHeader(), fx.bindToPayment(), "payment")),
                ReasonCode.CHAIN_MISSING);
        StampV1 notOrigin = StampSignerV1.sign("search", "s-1", "rid-1", Fixture.NOW, "b", "", fx.search.getPrivate());
        assertNoSuspect(fx.verifier().verify(fx.requestWithChain(new PathChainV1(List.of(notOrigin)))),
                ReasonCode.BAD_ORIGIN);
        StampV1 forged = StampSignerV1.sign("gateway", "evil", "rid-1", Fixture.NOW, fx.bindToPayment(), "", fx.search.getPrivate());
        assertNoSuspect(fx.verifier().verify(fx.requestWithChain(new PathChainV1(List.of(forged)))),
                ReasonCode.BAD_SIGNATURE);

        StampV1 s0 = fx.gatewayStamp();
        StampV1 unlinked = StampSignerV1.sign("orders", "ord-1", "rid-1", Fixture.NOW, fx.bindToPayment(),
                Base64Url.encode("not-s0-sig".getBytes()), fx.orders.getPrivate());
        assertNoSuspect(fx.verifier().verify(fx.requestWithChain(new PathChainV1(List.of(s0, unlinked)))),
                ReasonCode.BROKEN_LINK);

        // A genuine last stamp that belongs to someone else's request is not blamed.
        StampV1 otherRid = StampSignerV1.sign("orders", "ord-1", "rid-DIFFERENT", Fixture.NOW, fx.bindToPayment(), s0.sig(), fx.orders.getPrivate());
        assertNoSuspect(fx.verifier().verify(fx.requestWithChain(new PathChainV1(List.of(s0, otherRid)))),
                ReasonCode.RID_MISMATCH);
        StampV1 old0 = StampSignerV1.sign("gateway", "gw-1", "rid-1", Fixture.NOW - 6000, "bGW", "", fx.gateway.getPrivate());
        StampV1 old1 = StampSignerV1.sign("orders", "ord-1", "rid-1", Fixture.NOW - 6000, fx.bindToPayment(), old0.sig(), fx.orders.getPrivate());
        assertNoSuspect(fx.verifier().verify(fx.requestWithChain(new PathChainV1(List.of(old0, old1)))),
                ReasonCode.EXPIRED);
        assertNoSuspect(fx.verifier().verify(
                new VerifyRequestV1(fx.validChainHeader(), fx.validProofHeader(), fx.bindToPayment() + "-altered", "payment")),
                ReasonCode.BINDING_MISMATCH);
        VerifierV1 verifier = fx.verifier();
        assertTrue(verifier.verify(fx.validRequest()).ok());
        assertNoSuspect(verifier.verify(fx.validRequest()), ReasonCode.REPLAY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"svc", "inst", "rid", "ts", "bind", "prev", "sig"})
    void tamperingAnyLastStampFieldIsRejected(String field) {
        StampV1 s0 = fx.gatewayStamp();
        StampV1 good = StampSignerV1.sign("orders", "ord-1", "rid-1", Fixture.NOW, fx.bindToPayment(), s0.sig(), fx.orders.getPrivate());
        StampV1 tampered = switch (field) {
            case "svc" -> new StampV1("payment", good.inst(), good.rid(), good.ts(), good.bind(), good.prev(), good.sig());
            case "inst" -> new StampV1(good.svc(), "other", good.rid(), good.ts(), good.bind(), good.prev(), good.sig());
            case "rid" -> new StampV1(good.svc(), good.inst(), "rid-X", good.ts(), good.bind(), good.prev(), good.sig());
            case "ts" -> new StampV1(good.svc(), good.inst(), good.rid(), good.ts() + 1, good.bind(), good.prev(), good.sig());
            case "bind" -> new StampV1(good.svc(), good.inst(), good.rid(), good.ts(), "tampered", good.prev(), good.sig());
            case "prev" -> new StampV1(good.svc(), good.inst(), good.rid(), good.ts(), good.bind(), "tampered", good.sig());
            case "sig" -> new StampV1(good.svc(), good.inst(), good.rid(), good.ts(), good.bind(), good.prev(),
                    Base64Url.encode(Crypto.randomBytes(64)));
            default -> throw new IllegalArgumentException(field);
        };
        VerifyRequestV1 req = fx.requestWithChain(new PathChainV1(List.of(s0, tampered)));
        assertFalse(fx.verifier().verify(req).ok(), "tampering " + field + " must be rejected");
    }

    private static final ObjectMapper RAW = new ObjectMapper();

    private static String header(JsonNode node) throws Exception {
        return Base64Url.encode(RAW.writeValueAsBytes(node));
    }

    /** The valid chain as raw JSON with one field of the last stamp removed or set to JSON null. */
    private String chainWith(String field, boolean asNull) throws Exception {
        ArrayNode stamps = (ArrayNode) RAW.readTree(Json.write(fx.validChain().stamps()));
        ObjectNode last = (ObjectNode) stamps.get(stamps.size() - 1);
        if (asNull) {
            last.putNull(field);
        } else {
            last.remove(field);
        }
        return header(stamps);
    }

    @ParameterizedTest
    @ValueSource(strings = {"svc", "inst", "rid", "ts", "bind", "prev", "sig"})
    void stampMissingAFieldIsChainMissing(String field) throws Exception {
        VerifyRequestV1 req = new VerifyRequestV1(chainWith(field, false), fx.validProofHeader(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.CHAIN_MISSING, fx.verifier().verify(req).reason());
    }

    @ParameterizedTest
    @ValueSource(strings = {"svc", "inst", "rid", "ts", "bind", "prev", "sig"})
    void stampWithANullFieldIsChainMissing(String field) throws Exception {
        VerifyRequestV1 req = new VerifyRequestV1(chainWith(field, true), fx.validProofHeader(), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.CHAIN_MISSING, fx.verifier().verify(req).reason());
    }

    private String proofWith(String field, boolean asNull) throws Exception {
        ObjectNode proof = (ObjectNode) RAW.readTree(Json.write(fx.tree.proofFor("gateway/orders/payment")));
        if (asNull) {
            proof.putNull(field);
        } else {
            proof.remove(field);
        }
        return header(proof);
    }

    @ParameterizedTest
    @ValueSource(strings = {"leafSalt", "siblings", "dirs", "rootId"})
    void proofMissingAFieldIsPathNotAllowed(String field) throws Exception {
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), proofWith(field, false), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    @ParameterizedTest
    @ValueSource(strings = {"leafSalt", "siblings", "dirs", "rootId"})
    void proofWithANullFieldIsPathNotAllowed(String field) throws Exception {
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), proofWith(field, true), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    @Test
    void proofWithANullSiblingIsPathNotAllowed() throws Exception {
        ObjectNode proof = (ObjectNode) RAW.readTree(Json.write(fx.tree.proofFor("gateway/orders/payment")));
        ((ArrayNode) proof.get("siblings")).removeAll().addNull();
        VerifyRequestV1 req = new VerifyRequestV1(fx.validChainHeader(), header(proof), fx.bindToPayment(), "payment");
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, fx.verifier().verify(req).reason());
    }

    /** A valid scenario-1 world: keys, a salted tree, a signed root, and a configured verifier. */
    private static final class Fixture {
        static final long NOW = 1_000_000L;
        static final int DEPTH = 8;

        final KeyPair gateway = Crypto.generateEd25519KeyPair();
        final KeyPair orders = Crypto.generateEd25519KeyPair();
        final KeyPair search = Crypto.generateEd25519KeyPair();
        final KeyPair policy = Crypto.generateEd25519KeyPair();

        final Map<String, byte[]> salts = Map.of(
                "gateway/orders/payment", Crypto.randomBytes(16),
                "gateway/orders", Crypto.randomBytes(16),
                "gateway/search", Crypto.randomBytes(16));
        final MerkleTree tree = MerkleTree.build(
                List.of(
                        new MerkleLeaf(salts.get("gateway/orders/payment"), "gateway/orders/payment"),
                        new MerkleLeaf(salts.get("gateway/orders"), "gateway/orders"),
                        new MerkleLeaf(salts.get("gateway/search"), "gateway/search")),
                DEPTH, "v1");
        final SignedRoot signedRoot = SignedRoot.signOldForm(tree.root(), "v1", policy.getPrivate());
        final Keyring keyring = Keyring.of(Map.of(
                "gateway", gateway.getPublic(),
                "orders", orders.getPublic(),
                "search", search.getPublic()));

        String bindToPayment() {
            return "bind-pay";
        }

        StampV1 gatewayStamp() {
            return StampSignerV1.sign("gateway", "gw-1", "rid-1", NOW, "bindGatewayToOrders", "", gateway.getPrivate());
        }

        PathChainV1 validChain() {
            StampV1 s0 = gatewayStamp();
            StampV1 s1 = StampSignerV1.sign("orders", "ord-1", "rid-1", NOW, bindToPayment(), s0.sig(), orders.getPrivate());
            return new PathChainV1(List.of(s0, s1));
        }

        PathChainV1 gatewaySearchChain() {
            StampV1 s0 = gatewayStamp();
            StampV1 s1 = StampSignerV1.sign("search", "s-1", "rid-1", NOW, bindToPayment(), s0.sig(), search.getPrivate());
            return new PathChainV1(List.of(s0, s1));
        }

        String validChainHeader() {
            return validChain().encode();
        }

        String gatewaySearchChainHeader() {
            return gatewaySearchChain().encode();
        }

        String validProofHeader() {
            return tree.proofFor("gateway/orders/payment").encode();
        }

        String proofHeaderFor(String route) {
            return tree.proofFor(route).encode();
        }

        VerifyRequestV1 validRequest() {
            return new VerifyRequestV1(validChainHeader(), validProofHeader(), bindToPayment(), "payment");
        }

        VerifyRequestV1 requestWithChain(PathChainV1 chain) {
            return new VerifyRequestV1(chain.encode(), validProofHeader(), bindToPayment(), "payment");
        }

        VerifierV1 verifier() {
            VerifierConfigV1 cfg = VerifierConfigV1.pinned(
                    keyring, signedRoot, policy.getPublic(), Set.of("gateway"), 5000,
                    new InMemoryNonceCache(), () -> NOW);
            return new VerifierV1(cfg);
        }
    }
}
