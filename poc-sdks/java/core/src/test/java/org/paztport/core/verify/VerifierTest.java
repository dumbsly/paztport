// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
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
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;

/** The edges of the live verifier that the shared vectors do not reach: hostile input, a null peer, the pin. */
class VerifierTest {

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

    private static Verifier verifier() {
        JsonNode c = peerOk;
        JsonNode policy = vectors.get("policies").get(c.get("policy").asText());
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        c.get("keyring").properties().forEach(e -> keys.put(e.getKey(), Crypto.decodePublicKey(
                Base64Url.decode(vectors.get("keys").get(e.getValue().asText()).get("pub").asText()))));
        long now = c.get("now").asLong();
        return new Verifier(new VerifierConfig(List.of(new PinnedKeyring(Keyring.of(keys), NOT_AFTER)),
                List.of(new PinnedRoot(Base64Url.decode(policy.get("root").asText()), policy.get("rootId").asText(),
                        NOT_AFTER)), NOT_AFTER, Set.of("session"), c.get("sess").asText(),
                new InMemoryNonceCache(c.get("nonceTtlMs").asLong()), () -> now, c.get("callMaxAgeMs").asLong(),
                c.get("runMaxAgeMs").asLong()));
    }

    private static VerifyInput input(String stamps, String bind, String influence, String proof, Peer peer) {
        JsonNode policy = vectors.get("policies").get(peerOk.get("policy").asText());
        String good = Vectors.tokenText(policy.get("proofTokens").get(peerOk.get("proofRoute").asText()));
        return new VerifyInput(stamps, bind, influence, proof == null ? good : proof, peerOk.get("receiver").asText(),
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
        assertThrows(IllegalArgumentException.class, () -> VerifierConfig.pinned(List.of(unsigned),
                List.of(signed), pin, Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
        KeyringFile good = KeyringFile.sign(Map.of(), pin, NOT_AFTER, policy.getPrivate());
        VerifierConfig cfg = VerifierConfig.pinned(List.of(good), List.of(signed), pin, Set.of("session"), "s",
                new InMemoryNonceCache(), () -> 0L, 5000, 5000);
        assertEquals("v1", cfg.roots().get(0).rootId());
        KeyPair other = Crypto.generateEd25519KeyPair();
        SignedRoot forged = SignedRoot.sign(root, "v1", NOT_AFTER, other.getPrivate());
        assertThrows(IllegalArgumentException.class, () -> VerifierConfig.pinned(List.of(good), List.of(forged),
                pin, Set.of("session"), "s", new InMemoryNonceCache(), () -> 0L, 5000, 5000));
    }

    @Test
    void nullInputsAreRejectionsNotExceptions() {
        String chain = Vectors.tokenText(peerOk.get("chainToken"));
        String infl = Vectors.tokenText(peerOk.get("influenceToken"));
        VerifyInput good = input(chain, bind(), infl, null, null);
        assertEquals(ReasonCode.CHAIN_MISSING, verifier().verify(null).reason());
        assertEquals(ReasonCode.BINDING_MISMATCH, verifier().verify(new VerifyInput(chain, bind(), infl,
                good.proof(), null, true, good.nonceKey(), null)).reason());
        assertEquals(ReasonCode.REPLAY, verifier().verify(new VerifyInput(chain, bind(), infl, good.proof(),
                good.receiver(), true, null, null)).reason());
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, verifier().verify(new VerifyInput(chain, bind(), infl, null,
                good.receiver(), true, good.nonceKey(), null)).reason());
    }

    @Test
    void nullConfigIsRefused() {
        assertThrows(NullPointerException.class, () -> new Verifier(null));
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
        Stamp a = Stamp.sign(c.origin(), "i", "r", c.originTs(), "s", "pi", "b", "", "", SESSION.getPrivate());
        Stamp b = Stamp.sign("pi", "i", c.rid(), c.lastTs(), c.sess(), "target", "b", "",
                c.prev() == null ? a.sig() : c.prev(), PI.getPrivate());
        return Chains.toJson(List.of(a, b));
    }

    private static Verifier boundary(NonceCache cache, long callMax, long runMax) {
        Keyring ring = Keyring.of(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic(),
                "other", Crypto.generateEd25519KeyPair().getPublic()));
        return new Verifier(new VerifierConfig(List.of(new PinnedKeyring(ring, NOT_AFTER)),
                List.of(root(TREE, NOT_AFTER)), NOT_AFTER, Set.of("session"), "s", cache, () -> NOW, callMax, runMax));
    }

    private static ReasonCode run(Case c) {
        return run(c, new InMemoryNonceCache(2 * CALL));
    }

    private static ReasonCode run(Case c, NonceCache cache) {
        return boundary(cache, CALL, RUN).verify(new VerifyInput(chain(c), "b", null, PROOF, "target", true,
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

    private static VerifyInput boundaryInput(String nonceKey, Peer peer) {
        return new VerifyInput(chain(new Case()), "b", null, PROOF, "target", true, nonceKey, peer);
    }

    /** A verifier pinned to a keyring valid until {@code ringNotAfter} and a root until {@code rootNotAfter}. */
    private static Verifier pinnedAt(long[] clock, long ringNotAfter, long rootNotAfter) {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Map<String, String> services = Map.of(
                "session", Base64Url.encode(Crypto.encodePublicKey(SESSION.getPublic())),
                "pi", Base64Url.encode(Crypto.encodePublicKey(PI.getPublic())));
        KeyringFile ring = KeyringFile.sign(services, pin, ringNotAfter, policy.getPrivate());
        SignedRoot root = SignedRoot.sign(TREE.root(), "vtest", rootNotAfter, policy.getPrivate());
        return new Verifier(VerifierConfig.pinned(List.of(ring), List.of(root), pin, Set.of("session"), "s",
                new InMemoryNonceCache(2 * CALL), () -> clock[0], CALL, RUN));
    }

    @Test
    void expiresWhileRunning() {
        long[] clock = {NOW};
        Verifier v = pinnedAt(clock, NOW + 1000, NOW + 2000);
        assertEquals(ReasonCode.OK, v.verify(boundaryInput("k1", null)).reason());
        clock[0] = NOW + 1001;
        // The stamps are still fresh (within the call window), so only the keyring's window can refuse.
        assertEquals(new VerifyResult(ReasonCode.POLICY_EXPIRED, "", ""), v.verify(boundaryInput("k2", null)));
    }

    @Test
    void theEarlierWindowGoverns() {
        long[] clock = {NOW};
        Verifier v = pinnedAt(clock, NOW + 2000, NOW + 1000);
        assertEquals(ReasonCode.OK, v.verify(boundaryInput("k1", null)).reason());
        clock[0] = NOW + 1001;
        assertEquals(ReasonCode.POLICY_EXPIRED, v.verify(boundaryInput("k2", null)).reason());
    }

    @Test
    void atNotAfterStillVerifies() {
        long[] clock = {NOW};
        Verifier v = pinnedAt(clock, NOW, NOW);
        assertEquals(new VerifyResult(ReasonCode.OK, "pi", "i"), v.verify(boundaryInput("k1", null)));
        clock[0] = NOW + 1;
        assertEquals(ReasonCode.POLICY_EXPIRED, v.verify(boundaryInput("k2", null)).reason());
    }

    @Test
    void policyExpiredNamesNoPeerAndPrecedesEveryStampCheck() {
        long[] clock = {NOW};
        Verifier v = pinnedAt(clock, NOW, NOW);
        clock[0] = NOW + 1;
        VerifyResult none = new VerifyResult(ReasonCode.POLICY_EXPIRED, "", "");
        // Expiry is not the sender's fault, so even an authenticated peer is not named.
        assertEquals(none, v.verify(boundaryInput("k1", new Peer("pi", "10.0.0.7"))));
        assertEquals(none, v.verify(null));
        assertEquals(none, v.verify(new VerifyInput("\"x\"", "b", null, PROOF, "target", true, "k2",
                new Peer("search", "10.0.0.9"))));
    }

    @Test
    void anExpiredPolicySpendsNoNonce() {
        long[] clock = {NOW};
        Verifier v = pinnedAt(clock, NOW, NOW + 2000);
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
            Verifier v = new Verifier(new VerifierConfig(List.of(new PinnedKeyring(ring, NOT_AFTER)),
                    List.of(root(TREE, NOT_AFTER)), window, Set.of("session"), "s", new InMemoryNonceCache(2 * CALL),
                    () -> NOW, CALL, RUN));
            assertEquals(new VerifyResult(ReasonCode.POLICY_EXPIRED, "", ""), v.verify(boundaryInput("k1", null)),
                    String.valueOf(window));
        }
        Keyring ring = Keyring.of(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()));
        Verifier largest = new Verifier(new VerifierConfig(List.of(new PinnedKeyring(ring, NOT_AFTER)),
                List.of(root(TREE, NOT_AFTER)), JsonIntegers.MAX_SAFE, Set.of("session"), "s",
                new InMemoryNonceCache(2 * CALL), () -> NOW, CALL, RUN));
        assertEquals(ReasonCode.OK, largest.verify(boundaryInput("k1", null)).reason());
    }

    // Several pinned keyrings and roots, as while a rollover is under way: only those current at now are used.

    private static final KeyPair OLD_PI = Crypto.generateEd25519KeyPair();
    /** The same route under a second policy, the first tree renewed under its rootId, and a tree pinned nowhere. */
    private static final MerkleTree SECOND = tree("v2", 1);
    private static final MerkleTree RENEWED = tree("vtest", 2);
    private static final MerkleTree UNPINNED = tree("v3", 3);
    private static final VerifyResult OK_PI = new VerifyResult(ReasonCode.OK, "pi", "i");
    private static final VerifyResult DENIED = new VerifyResult(ReasonCode.PATH_NOT_ALLOWED, "pi", "i");
    private static final VerifyResult UNSIGNED = new VerifyResult(ReasonCode.BAD_SIGNATURE, "", "");

    /** A one-leaf tree for the boundary route, its salt filled with {@code salt} so each tree has its own root. */
    private static MerkleTree tree(String rootId, int salt) {
        byte[] bytes = new byte[16];
        Arrays.fill(bytes, (byte) salt);
        return MerkleTree.build(List.of(new MerkleLeaf(bytes, "session/pi/target")), 1, rootId);
    }

    private static PinnedKeyring ring(Map<String, PublicKey> keys, long notAfter) {
        return new PinnedKeyring(Keyring.of(keys), notAfter);
    }

    private static PinnedKeyring ring(Map<String, PublicKey> keys) {
        return ring(keys, NOT_AFTER);
    }

    private static PinnedRoot root(MerkleTree tree, long notAfter) {
        return new PinnedRoot(tree.root(), tree.rootId(), notAfter);
    }

    private static PinnedRoot root(MerkleTree tree) {
        return root(tree, NOT_AFTER);
    }

    private static String proofOf(MerkleTree tree) {
        return tree.proofFor("session/pi/target").toJson();
    }

    /** {@code tree}'s proof, its {@code rootId} relabelled as {@code rootId}. */
    private static String relabelled(MerkleTree tree, String rootId) {
        MerkleProof p = tree.proofFor("session/pi/target");
        return new MerkleProof(p.leafSalt(), p.siblings(), p.dirs(), rootId).toJson();
    }

    /** The boundary chain at {@code NOW}, checked against these keyrings and roots with {@code proof}. */
    private static VerifyResult under(List<PinnedKeyring> keyrings, List<PinnedRoot> roots, String proof) {
        Verifier v = new Verifier(new VerifierConfig(keyrings, roots, NOT_AFTER, Set.of("session"), "s",
                new InMemoryNonceCache(2 * CALL), () -> NOW, CALL, RUN));
        return v.verify(new VerifyInput(chain(new Case()), "b", null, proof, "target", true, "k", null));
    }

    private static VerifyResult keyedBy(PinnedKeyring... keyrings) {
        return under(List.of(keyrings), List.of(root(TREE)), PROOF);
    }

    private static VerifyResult provenBy(String proof, PinnedRoot... roots) {
        return under(List.of(ring(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()))), List.of(roots),
                proof);
    }

    @Test
    void aStampVerifiesUnderAKeyOnlyInTheSecondKeyring() {
        // The first keyring has pi's old key, or none: each key the current keyrings give pi is tried.
        assertEquals(OK_PI, keyedBy(ring(Map.of("session", SESSION.getPublic(), "pi", OLD_PI.getPublic())),
                ring(Map.of("pi", PI.getPublic()))));
        assertEquals(OK_PI, keyedBy(ring(Map.of("session", SESSION.getPublic())),
                ring(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()))));
    }

    @Test
    void aChainMayTakeItsKeysFromTwoKeyrings() {
        assertEquals(OK_PI, keyedBy(ring(Map.of("session", SESSION.getPublic())), ring(Map.of("pi", PI.getPublic()))));
        assertEquals(OK_PI, keyedBy(ring(Map.of("pi", PI.getPublic())), ring(Map.of("session", SESSION.getPublic()))));
    }

    @Test
    void aKeyOnlyInAnExpiredKeyringIsBadSignature() {
        assertEquals(UNSIGNED, keyedBy(ring(Map.of("session", SESSION.getPublic(), "pi", OLD_PI.getPublic())),
                ring(Map.of("pi", PI.getPublic()), NOW - 1)));
        assertEquals(UNSIGNED, keyedBy(ring(Map.of("session", SESSION.getPublic())),
                ring(Map.of("pi", PI.getPublic()), NOW - 1)));
    }

    /** A key is looked up by the stamp's own service name: pi's key filed under another name signs nothing. */
    @Test
    void aKeyUnderAnotherNameIsBadSignature() {
        assertEquals(OK_PI, keyedBy(ring(Map.of("session", SESSION.getPublic(), "pi", PI.getPublic()))));
        assertEquals(UNSIGNED, keyedBy(ring(Map.of("session", SESSION.getPublic(), "other", PI.getPublic()))));
        assertEquals(UNSIGNED, keyedBy(ring(Map.of("session", SESSION.getPublic(), "pi", OLD_PI.getPublic())),
                ring(Map.of("Pi", PI.getPublic(), "pi-1", PI.getPublic(), "session", PI.getPublic()))));
    }

    @Test
    void aProofUnderTheSecondRootProves() {
        assertEquals(OK_PI, provenBy(proofOf(SECOND), root(TREE), root(SECOND)));
        assertEquals(OK_PI, provenBy(proofOf(TREE), root(TREE), root(SECOND)));
    }

    @Test
    void aProofWhoseRootIdIsPinnedNowhereIsPathNotAllowed() {
        assertEquals(DENIED, provenBy(proofOf(UNPINNED), root(TREE), root(SECOND)));
    }

    /**
     * The proof's rootId selects the root it is checked against: one tree's proof relabelled with the other current
     * root's rootId is checked against that root, and proves nothing, though it would prove against its own.
     */
    @Test
    void aProofRelabelledWithTheOtherCurrentRootsIdIsPathNotAllowed() {
        assertEquals(DENIED, provenBy(relabelled(SECOND, "vtest"), root(TREE), root(SECOND)));
        assertEquals(DENIED, provenBy(relabelled(TREE, "v2"), root(TREE), root(SECOND)));
        assertEquals(DENIED, provenBy(relabelled(TREE, "v2"), root(SECOND), root(TREE)));
    }

    @Test
    void aProofUnderAnExpiredRootIsPathNotAllowedWhileAnotherIsCurrent() {
        assertEquals(DENIED, provenBy(proofOf(TREE), root(TREE, NOW - 1), root(SECOND)));
        assertEquals(OK_PI, provenBy(proofOf(SECOND), root(TREE, NOW - 1), root(SECOND)));
    }

    @Test
    void twoRootsSharingARootIdBothServe() {
        assertEquals(OK_PI, provenBy(proofOf(TREE), root(TREE), root(RENEWED)));
        assertEquals(OK_PI, provenBy(proofOf(RENEWED), root(TREE), root(RENEWED)));
        // The renewal's tree is not the old one's: each proof proves against its own root only.
        assertEquals(DENIED, provenBy(proofOf(RENEWED), root(TREE)));
    }

    @Test
    void aMemberAtNowIsCurrentAndOneMsPastIsNot() {
        PinnedKeyring session = ring(Map.of("session", SESSION.getPublic()));
        assertEquals(OK_PI, keyedBy(session, ring(Map.of("pi", PI.getPublic()), NOW)));
        assertEquals(UNSIGNED, keyedBy(session, ring(Map.of("pi", PI.getPublic()), NOW - 1)));
        assertEquals(OK_PI, provenBy(PROOF, root(TREE, NOW)));
        assertEquals(DENIED, provenBy(PROOF, root(TREE, NOW - 1)));
    }

    /**
     * A member's window is a protocol integer, or {@link Long#MAX_VALUE} for none; any other is current at no time,
     * as no signed object carries one.
     */
    @Test
    void aMemberWindowOutOfRangeIsNeverCurrent() {
        PinnedKeyring session = ring(Map.of("session", SESSION.getPublic()));
        assertEquals(OK_PI, keyedBy(session, ring(Map.of("pi", PI.getPublic()), JsonIntegers.MAX_SAFE)));
        assertEquals(OK_PI, keyedBy(session, ring(Map.of("pi", PI.getPublic()), Long.MAX_VALUE)));
        assertEquals(OK_PI, provenBy(PROOF, root(TREE, Long.MAX_VALUE)));
        for (long window : new long[] {JsonIntegers.MAX_SAFE + 1, Long.MAX_VALUE - 1, -1, Long.MIN_VALUE}) {
            String at = String.valueOf(window);
            assertEquals(UNSIGNED, keyedBy(session, ring(Map.of("pi", PI.getPublic()), window)), at);
            assertEquals(DENIED, provenBy(PROOF, root(TREE, window)), at);
        }
    }
}
