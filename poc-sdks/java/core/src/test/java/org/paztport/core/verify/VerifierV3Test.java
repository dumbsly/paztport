// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.Vectors;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleLeaf;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.StampV3;

/** The edges of the v3 live verifier that the shared vectors do not reach: hostile input, a null peer, the pin. */
class VerifierV3Test {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static JsonNode vectors;
    private static JsonNode peerOk;

    @BeforeAll
    static void load() throws IOException {
        vectors = Vectors.load("v3.json");
        for (JsonNode c : vectors.get("verify")) {
            if (c.get("name").asText().equals("peer ok")) {
                peerOk = c;
            }
        }
    }

    private static VerifierV3 verifier() {
        JsonNode c = peerOk;
        JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        c.get("keyring").properties().forEach(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(vectors.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        long now = c.get("now").asLong();
        return new VerifierV3(new VerifierConfigV3(Keyring.of(keys), Base64Url.decode(policy.get("root").asText()),
                policy.get("rootId").asText(), NOT_AFTER, Set.of("session"), c.get("sess").asText(),
                new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now, c.get("callMaxAgeMs").asLong(),
                c.get("runMaxAgeMs").asLong()));
    }

    private static VerifyInputV3 input(String stamps, String bind, String influence, String proof, Peer peer) {
        JsonNode policy = vectors.get("policies").get(peerOk.get("policy").asText());
        String good = Vectors.tokenText(policy.get("proofTokens").get(peerOk.get("proofRoute").asText()));
        return new VerifyInputV3(stamps, bind, influence, proof == null ? good : proof, peerOk.get("receiver").asText(),
                peerOk.get("receiverInRoute").asBoolean(), peerOk.get("nonceKey").asText(), peer);
    }

    private static String bind() {
        return peerOk.get("expectedBind").asText();
    }

    @Test
    void neverThrows() {
        String chain = Vectors.tokenText(peerOk.get("chainToken"));
        String infl = Vectors.tokenText(peerOk.get("influenceToken"));
        assertEquals(ReasonCode.CHAIN_MISSING,
                verifier().verify(input("\"x\"", bind(), infl, null, null)).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(input(null, bind(), infl, null, null)).reason());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH,
                verifier().verify(input(chain, bind(), "{}", null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED,
                verifier().verify(input(chain, bind(), infl, "\"x\"", null)).reason());
        // Text that is not JSON at all fails at the check that reads it, as a wrong type does.
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(input(chain + "]", bind(), infl, null, null))
                .reason());
        assertEquals(ReasonCode.INFLUENCE_MISMATCH,
                verifier().verify(input(chain, bind(), "[", null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED,
                verifier().verify(input(chain, bind(), infl, "{", null)).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(input(chain, null, infl, null, null)).reason());
    }

    @Test
    void nullPeerIsNoPeer() {
        VerifyResult r = verifier().verify(input(Vectors.tokenText(peerOk.get("chainToken")), bind(),
                Vectors.tokenText(peerOk.get("influenceToken")), null, null));
        assertEquals(new VerifyResult(ReasonCode.OK, "pi", "pi-1"), r);
    }

    @Test
    void pinnedRefusesUnsignedKeyring() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        byte[] root = new byte[32];
        SignedRoot signed = SignedRoot.sign(root, "v1", NOT_AFTER, policy.getPrivate());
        KeyringFile unsigned = new KeyringFile(Map.of(), pin, null, NOT_AFTER);
        assertThrows(IllegalArgumentException.class, () -> VerifierConfigV3.pinned(unsigned, signed, pin,
                Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
        KeyringFile good = KeyringFile.sign(Map.of(), pin, NOT_AFTER, policy.getPrivate());
        VerifierConfigV3 cfg = VerifierConfigV3.pinned(good, signed, pin, Set.of("session"), "s",
                new InMemoryNonceCache(), () -> 0L, 5000, 5000);
        assertEquals("v1", cfg.rootId());
        KeyPair other = Crypto.generateEd25519KeyPair();
        SignedRoot forged = SignedRoot.sign(root, "v1", NOT_AFTER, other.getPrivate());
        assertThrows(IllegalArgumentException.class, () -> VerifierConfigV3.pinned(good, forged, pin,
                Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
    }

    @Test
    void nullInputsAreRejectionsNotExceptions() {
        String chain = Vectors.tokenText(peerOk.get("chainToken"));
        String infl = Vectors.tokenText(peerOk.get("influenceToken"));
        VerifyInputV3 good = input(chain, bind(), infl, null, null);
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(null).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(new VerifyInputV3(chain, bind(), infl,
                good.proof(), null, true, good.nonceKey(), null)).reason());
        assertEquals(ReasonCode.REPLAY, verifier().verify(new VerifyInputV3(chain, bind(), infl, good.proof(),
                good.receiver(), true, null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(new VerifyInputV3(chain, bind(), infl, null,
                good.receiver(), true, good.nonceKey(), null)).reason());
    }

    @Test
    void nullConfigIsRefused() {
        assertThrows(NullPointerException.class, () -> new VerifierV3(null));
    }

    // Boundary cases, on chains the test signs itself so each reaches exactly the check it targets.

    private static final long NOW = 1_000_000_000L;
    private static final long CALL = 5000;
    private static final long RUN = 60_000;

    private static final KeyPair SESSION = Crypto.generateEd25519KeyPair();
    private static final KeyPair PI = Crypto.generateEd25519KeyPair();
    private static final MerkleTree TREE = MerkleTree.build(
            List.of(new MerkleLeaf(new byte[16], "session/pi/target")), 1, "vtest");
    private static final String PROOF = TREE.proofFor("session/pi/target").toJson();

    private record Case(String origin, String rid, String sess, String prev, long originTs, long lastTs) {
        Case() {
            this("session", "r", "s", null, NOW - 100, NOW - 50);
        }

        Case origin(String o) {
            return new Case(o, rid, sess, prev, originTs, lastTs);
        }

        Case rid(String r) {
            return new Case(origin, r, sess, prev, originTs, lastTs);
        }

        Case sess(String s) {
            return new Case(origin, rid, s, prev, originTs, lastTs);
        }

        Case prev(String p) {
            return new Case(origin, rid, sess, p, originTs, lastTs);
        }

        Case originTs(long t) {
            return new Case(origin, rid, sess, prev, t, lastTs);
        }

        Case lastTs(long t) {
            return new Case(origin, rid, sess, prev, originTs, t);
        }
    }

    private static String chain(Case c) {
        StampV3 a = StampV3.sign(c.origin(), "i", "r", c.originTs(), "s", "pi", "b", "", "", SESSION.getPrivate());
        StampV3 b = StampV3.sign("pi", "i", c.rid(), c.lastTs(), c.sess(), "target", "b", "",
                c.prev() == null ? a.sig() : c.prev(), PI.getPrivate());
        return Chains.toJson(List.of(a, b));
    }

    private static VerifierV3 boundary(NonceCache cache, long callMax, long runMax) {
        Keyring ring = Keyring.of(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic(),
                "other", Crypto.generateEd25519KeyPair().getPublic()));
        return new VerifierV3(new VerifierConfigV3(ring, TREE.root(), "vtest", NOT_AFTER, Set.of("session"), "s", cache,
                () -> NOW, callMax, runMax));
    }

    private static ReasonCode run(Case c) {
        return run(c, new InMemoryNonceCache(2 * CALL));
    }

    private static ReasonCode run(Case c, NonceCache cache) {
        return boundary(cache, CALL, RUN).verify(new VerifyInputV3(chain(c), "b", null, PROOF, "target", true,
                "r|target|req", null)).reason();
    }

    @Test
    void lastStampAgeBoundary() {
        assertEquals(ReasonCode.OK, run(new Case().lastTs(NOW - CALL)));
        assertEquals(ReasonCode.EXPIRED, run(new Case().lastTs(NOW - CALL - 1)));
        assertEquals(ReasonCode.OK, run(new Case().lastTs(NOW + CALL).originTs(NOW)));
        assertEquals(ReasonCode.EXPIRED, run(new Case().lastTs(NOW + CALL + 1).originTs(NOW)));
    }

    @Test
    void originAgeBoundary() {
        assertEquals(ReasonCode.OK, run(new Case().originTs(NOW - RUN)));
        assertEquals(ReasonCode.EXPIRED, run(new Case().originTs(NOW - RUN - 1)));
        assertEquals(ReasonCode.OK, run(new Case().originTs(NOW + CALL)));
        assertEquals(ReasonCode.EXPIRED, run(new Case().originTs(NOW + CALL + 1)));
    }

    @Test
    void nonceTtlMustCoverTwiceTheCallWindowAndIsNotSpentOtherwise() {
        assertEquals(ReasonCode.OK, run(new Case(), new InMemoryNonceCache(2 * CALL)));
        boolean[] touched = {false};
        NonceCache short1 = new NonceCache() {
            @Override
            public boolean seenBefore(String key, long now) {
                touched[0] = true;
                return false;
            }

            @Override
            public long ttlMs() {
                return 2 * CALL - 1;
            }
        };
        assertEquals(ReasonCode.REPLAY, run(new Case(), short1));
        assertEquals(false, touched[0], "a too-short cache is refused before the nonce is spent");
    }

    @Test
    void earlyChecksEachFailWithTheirOwnCode() {
        assertEquals(ReasonCode.BAD_ORIGIN, run(new Case().origin("other")));
        assertEquals(ReasonCode.BROKEN_LINK, run(new Case().prev("wrong")));
        assertEquals(ReasonCode.RID_MISMATCH, run(new Case().rid("r2")));
        assertEquals(ReasonCode.SESSION_UNKNOWN, run(new Case().sess("s2")));
    }

    @Test
    void aFailingNonceCacheOrClockPropagates() {
        NonceCache broken = new NonceCache() {
            @Override
            public boolean seenBefore(String key, long now) {
                throw new IllegalStateException("cache down");
            }

            @Override
            public long ttlMs() {
                return 2 * CALL;
            }
        };
        assertThrows(IllegalStateException.class, () -> run(new Case(), broken));
    }

    // The pinned policy's own window: checked before anything about the request, and blaming no one.

    private static VerifyInputV3 boundaryInput(String nonceKey, Peer peer) {
        return new VerifyInputV3(chain(new Case()), "b", null, PROOF, "target", true, nonceKey, peer);
    }

    /** A verifier pinned to a keyring valid until {@code ringNotAfter} and a root until {@code rootNotAfter}. */
    private static VerifierV3 pinnedAt(long[] clock, long ringNotAfter, long rootNotAfter) {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Map<String, String> services = Map.of(
                "session", Base64Url.encode(Crypto.encodePublicKey(SESSION.getPublic())),
                "pi", Base64Url.encode(Crypto.encodePublicKey(PI.getPublic())));
        KeyringFile ring = KeyringFile.sign(services, pin, ringNotAfter, policy.getPrivate());
        SignedRoot root = SignedRoot.sign(TREE.root(), "vtest", rootNotAfter, policy.getPrivate());
        return new VerifierV3(VerifierConfigV3.pinned(ring, root, pin, Set.of("session"), "s",
                new InMemoryNonceCache(2 * CALL), () -> clock[0], CALL, RUN));
    }

    @Test
    void expiresWhileRunning() {
        long[] clock = {NOW};
        VerifierV3 v = pinnedAt(clock, NOW + 1000, NOW + 2000);
        assertEquals(ReasonCode.OK, v.verify(boundaryInput("k1", null)).reason());
        clock[0] = NOW + 1001;
        // The stamps are still fresh (within the call window), so only the keyring's window can refuse.
        assertEquals(new VerifyResult(ReasonCode.POLICY_EXPIRED, "", ""), v.verify(boundaryInput("k2", null)));
    }

    @Test
    void theEarlierWindowGoverns() {
        long[] clock = {NOW};
        VerifierV3 v = pinnedAt(clock, NOW + 2000, NOW + 1000);
        assertEquals(ReasonCode.OK, v.verify(boundaryInput("k1", null)).reason());
        clock[0] = NOW + 1001;
        assertEquals(ReasonCode.POLICY_EXPIRED, v.verify(boundaryInput("k2", null)).reason());
    }

    @Test
    void atNotAfterStillVerifies() {
        long[] clock = {NOW};
        VerifierV3 v = pinnedAt(clock, NOW, NOW);
        assertEquals(new VerifyResult(ReasonCode.OK, "pi", "i"), v.verify(boundaryInput("k1", null)));
        clock[0] = NOW + 1;
        assertEquals(ReasonCode.POLICY_EXPIRED, v.verify(boundaryInput("k2", null)).reason());
    }

    @Test
    void policyExpiredNamesNoPeerAndPrecedesEveryStampCheck() {
        long[] clock = {NOW};
        VerifierV3 v = pinnedAt(clock, NOW, NOW);
        clock[0] = NOW + 1;
        VerifyResult none = new VerifyResult(ReasonCode.POLICY_EXPIRED, "", "");
        // Expiry is not the sender's fault, so even an authenticated peer is not named.
        assertEquals(none, v.verify(boundaryInput("k1", new Peer("pi", "10.0.0.7"))));
        assertEquals(none, v.verify(null));
        assertEquals(none, v.verify(new VerifyInputV3("\"x\"", "b", null, PROOF, "target", true, "k2",
                new Peer("search", "10.0.0.9"))));
    }

    @Test
    void anExpiredPolicySpendsNoNonce() {
        long[] clock = {NOW};
        VerifierV3 v = pinnedAt(clock, NOW, NOW + 2000);
        clock[0] = NOW + 1;
        assertEquals(ReasonCode.POLICY_EXPIRED, v.verify(boundaryInput("k1", null)).reason());
        clock[0] = NOW;
        assertEquals(ReasonCode.OK, v.verify(boundaryInput("k1", null)).reason(), "the refused call's key is unspent");
    }

    /**
     * A config built directly, as tests and vectors do, with a window outside [0, 2^53 &minus; 1]: no signed object
     * carries one, so check 0 refuses every request rather than reading 2^53 as a window that never closes.
     */
    @Test
    void aWindowOutOfRangeIsPolicyExpired() {
        for (long window : new long[] {JsonIntegers.MAX_SAFE + 1, Long.MAX_VALUE, -1, Long.MIN_VALUE}) {
            Keyring ring = Keyring.of(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()));
            VerifierV3 v = new VerifierV3(new VerifierConfigV3(ring, TREE.root(), "vtest", window, Set.of("session"),
                    "s", new InMemoryNonceCache(2 * CALL), () -> NOW, CALL, RUN));
            assertEquals(new VerifyResult(ReasonCode.POLICY_EXPIRED, "", ""), v.verify(boundaryInput("k1", null)),
                    String.valueOf(window));
        }
        Keyring ring = Keyring.of(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()));
        VerifierV3 largest = new VerifierV3(new VerifierConfigV3(ring, TREE.root(), "vtest", JsonIntegers.MAX_SAFE,
                Set.of("session"), "s", new InMemoryNonceCache(2 * CALL), () -> NOW, CALL, RUN));
        assertEquals(ReasonCode.OK, largest.verify(boundaryInput("k1", null)).reason());
    }
}
