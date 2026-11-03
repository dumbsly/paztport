// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.offline.OfflineConfig;
import org.paztport.core.offline.OfflineInput;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.offline.OfflineVerifier;
import org.paztport.core.offline.RecordedTimes;
import org.paztport.core.offline.Signers;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.MerkleLeaf;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;

/**
 * Offline-only behaviour the vectors do not pin: totality, the optional inputs, and the age limits, each of which
 * not configured is its live default on its own.
 */
class OfflineVerifierTest {

    /** A second tree for the good call's route, under another rootId; built once, as its padding is random. */
    private static MerkleTree second;

    @BeforeAll
    static void load() throws IOException {
        VectorsV3Test.load();
        second = MerkleTree.build(List.of(new MerkleLeaf(new byte[16], good().get("proofRoute").asText())), 1,
                "second");
    }

    private static JsonNode good() {
        return VectorsV3Test.offlineCase("recorded call");
    }

    private static OfflineResult run(OfflineInput in, OfflineConfig cfg) {
        return OfflineVerifier.verify(in, cfg);
    }

    private static OfflineConfig cfg(JsonNode c, Long runMax, Long callMax, Signers signers) {
        OfflineConfig b = VectorsV3Test.offlineConfig(c);
        return new OfflineConfig(b.keyrings(), b.roots(), b.allowedOrigins(), b.sess(), b.seen(), signers, runMax,
                callMax);
    }

    private static OfflineInput with(OfflineInput i, String stamps, RecordedTimes t, String prompt, String nonce) {
        return new OfflineInput(stamps, i.expectedBind(), i.influence(), i.proof(), i.receiver(),
                i.receiverInRoute(), nonce, i.rid(), t, prompt);
    }

    /**
     * The good call's chain with {@code v} set to {@code version} on the stamps at {@code positions}, written as its
     * JCS text, so a stamp is refused for its version alone.
     */
    private static OfflineResult withVersions(int version, int... positions) {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        List<Map<String, JsonValue>> stamps = new ArrayList<>();
        Chains.parse(in.stamps()).stamps().forEach(s -> stamps.add(new LinkedHashMap<>(
                ((JsonValue.Obj) JsonReader.wireText(s.toJson())).members())));
        for (int i : positions) {
            stamps.get(i).put("v", new JsonValue.Int(version));
        }
        String chain = JsonWriter.text(new JsonValue.Arr(stamps.stream().map(s -> (JsonValue) new JsonValue.Obj(s))
                .toList()));
        return run(with(in, chain, in.recordedTs(), in.prompt(), in.nonceKey()),
                VectorsV3Test.offlineConfig(c));
    }

    @Test
    void aStampWhoseVersionIsNotThreeIsChainMissing() {
        int last = VectorsV3Test.offlineCase("recorded call").get("chain").size() - 1;
        int[] all = IntStream.rangeClosed(0, last).toArray();
        assertEquals(ReasonCode.OK, withVersions(3, all).reason(), "the same chain, written the same way, with v 3");
        for (int version : new int[] {1, 2, 4}) {
            for (int[] positions : new int[][] {{0}, {last}, all}) {
                assertEquals(ReasonCode.CHAIN_MISSING, withVersions(version, positions).reason(),
                        "v " + version + " at " + Arrays.toString(positions));
            }
        }
    }

    @Test
    void neverThrows() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c);
        assertEquals(ReasonCode.CHAIN_MISSING, run(with(in, "\"x\"", in.recordedTs(), in.prompt(),
                in.nonceKey()), cfg).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, run(null, cfg).reason());
    }

    @Test
    void noRecordedTimeIsATimeMismatch() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.TIME_MISMATCH,
                run(with(in, in.stamps(), null, in.prompt(), in.nonceKey()), VectorsV3Test.offlineConfig(c)).reason());
    }

    @Test
    void theRunsRecordedStartTimesMustIncludeTheOrigins() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        long last = in.recordedTs().last();
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c);
        assertEquals(ReasonCode.TIME_MISMATCH, run(with(in, in.stamps(), new RecordedTimes(last, Set.of(1L)),
                in.prompt(), in.nonceKey()), cfg).reason());
        long origin = c.get("chain").get(0).get("ts").asLong();
        assertEquals(ReasonCode.OK, run(with(in, in.stamps(), new RecordedTimes(last, Set.of(origin)),
                in.prompt(), "k2"), cfg).reason());
    }

    private static final long NOT_AFTER = 4_102_444_800_000L;

    /**
     * A three-service call (gateway, orders, payment) whose origin stamp is made at {@code originTs} and whose last
     * stamp at {@code lastTs}, judged offline under {@code runMax} and {@code callMax}.
     */
    private static ReasonCode judgeAge(long originTs, long lastTs, Long runMax, Long callMax) {
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        KeyPair orders = Crypto.generateEd25519KeyPair();
        KeyPair policyKey = Crypto.generateEd25519KeyPair();
        PolicyBuilder.Result policy = PolicyBuilder.build(List.of(List.of("gateway", "orders", "payment")), 4,
                NOT_AFTER, policyKey.getPrivate());
        Stamper first = new Stamper("gateway", "gateway-1", gateway.getPrivate(), true, () -> "rid-1",
                () -> originTs);
        Stamper second = new Stamper("orders", "orders-1", orders.getPrivate(), false, () -> "rid-1",
                () -> lastTs);
        List<Stamp> hop = first.next(List.of(), "orders", Bindings.prompt("do it"), List.of(),
                policy.bundles().get("gateway")).chain();
        Stamper.Stamped sent = second.next(hop, "payment", "b2", List.of(), policy.bundles().get("orders"));
        OfflineConfig cfg = new OfflineConfig(
                List.of(new PinnedKeyring(Keyring.of(Map.of("gateway", gateway.getPublic(), "orders",
                        orders.getPublic())), Long.MAX_VALUE)),
                List.of(new PinnedRoot(policy.signedRoot().rootBytes(), policy.signedRoot().rootId(), Long.MAX_VALUE)),
                Set.of("gateway"), "", new LinkedHashSet<>(), null, runMax, callMax);
        OfflineInput in = new OfflineInput(Chains.toJson(sent.chain()), "b2", null, sent.proof().toJson(), "payment",
                true, "k", null, new RecordedTimes(lastTs, Set.of(originTs)), "do it");
        return run(in, cfg).reason();
    }

    private static final long T = 10_000_000L;

    @Test
    void aMissingRunLimitIsTheLiveDefault() {
        long run = VerifierConfig.RUN_MAX_AGE_MS;
        for (Long call : new Long[] {null, VerifierConfig.CALL_MAX_AGE_MS}) {
            assertEquals(ReasonCode.OK, judgeAge(T, T + run, null, call), "a chain as long as the default passes");
            assertEquals(ReasonCode.EXPIRED, judgeAge(T, T + run + 1, null, call), "one ms longer is expired");
        }
    }

    @Test
    void aMissingCallLimitIsTheLiveDefault() {
        long call = VerifierConfig.CALL_MAX_AGE_MS;
        for (Long run : new Long[] {null, VerifierConfig.RUN_MAX_AGE_MS}) {
            assertEquals(ReasonCode.OK, judgeAge(T + call, T, run, null), "an origin as far after as the default");
            assertEquals(ReasonCode.EXPIRED, judgeAge(T + call + 1, T, run, null), "one ms further is expired");
        }
    }

    @Test
    void aGivenLimitStandsAlongsideTheOthersDefault() {
        assertEquals(ReasonCode.OK, judgeAge(T, T + 60_000, 60_000L, null));
        assertEquals(ReasonCode.EXPIRED, judgeAge(T, T + 60_001, 60_000L, null));
        assertEquals(ReasonCode.OK, judgeAge(T + 100, T, null, 100L));
        assertEquals(ReasonCode.EXPIRED, judgeAge(T + 101, T, null, 100L));
    }

    @Test
    void noPromptCanNeverBeBound() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.PROMPT_MISMATCH, run(with(in, in.stamps(), in.recordedTs(), null, in.nonceKey()),
                VectorsV3Test.offlineConfig(c)).reason());
    }

    @Test
    void aSpentNonceIsRecordedAndRefusedOnTheSecondUse() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c);
        assertEquals(ReasonCode.OK, run(in, cfg).reason());
        assertTrue(cfg.seen().contains(in.nonceKey()));
        assertEquals(ReasonCode.REPLAY, run(in, cfg).reason());
        OfflineInput none = with(in, in.stamps(), in.recordedTs(), in.prompt(), null);
        assertEquals(ReasonCode.REPLAY, run(none, VectorsV3Test.offlineConfig(c)).reason());
    }

    @Test
    void expectedSignersBindTheInstanceAndServices() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.OK,
                run(in, cfg(c, 1_800_000L, 5000L, new Signers(List.of("session", "pi"), "pi-1"))).reason());
        assertEquals(ReasonCode.BAD_ORIGIN,
                run(in, cfg(c, 1_800_000L, 5000L, new Signers(List.of("session", "pi"), "other"))).reason());
        assertEquals(ReasonCode.BAD_SIGNATURE,
                run(in, cfg(c, 1_800_000L, 5000L, new Signers(List.of("session", "x"), "pi-1"))).reason());
    }

    @Test
    void aPromptWithALoneSurrogateIsNeverBound() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        for (String p : new String[] {"a\uD800b", "a\uDC00b"}) {
            assertEquals(ReasonCode.PROMPT_MISMATCH, run(with(in, in.stamps(), in.recordedTs(), p, in.nonceKey()),
                    VectorsV3Test.offlineConfig(c)).reason());
        }
    }

    // Pinned keyrings and roots, each counting for a record no later than its notAfter.

    private static final KeyPair OTHER = Crypto.generateEd25519KeyPair();

    /** The good call's case keyring as one {@link Keyring}, from the vectors' keys. */
    private static Keyring keys() {
        return VectorsV3Test.keyring(good().get("keyring"));
    }

    /** The good call's keyring with pi's key swapped for one that signed nothing. */
    private static Keyring rotated() {
        return Keyring.of(Map.of("session", keys().keyFor("session"), "pi", OTHER.getPublic()));
    }

    private static PinnedRoot goodRoot(long notAfter) {
        OfflineConfig b = VectorsV3Test.offlineConfig(good());
        return new PinnedRoot(b.roots().get(0).root(), b.roots().get(0).rootId(), notAfter);
    }

    private static PinnedRoot secondRoot(long notAfter) {
        return new PinnedRoot(second.root(), second.rootId(), notAfter);
    }

    /** The good call, its proof {@code proof} when non-null, judged against these keyrings and roots. */
    private static OfflineResult judged(List<PinnedKeyring> keyrings, List<PinnedRoot> roots, String proof,
            Set<String> seen) {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig b = VectorsV3Test.offlineConfig(c);
        OfflineInput at = new OfflineInput(in.stamps(), in.expectedBind(), in.influence(),
                proof == null ? in.proof() : proof, in.receiver(), in.receiverInRoute(), in.nonceKey(), in.rid(),
                in.recordedTs(), in.prompt());
        return run(at, new OfflineConfig(keyrings, roots, b.allowedOrigins(), b.sess(), seen, null, null, null));
    }

    private static ReasonCode judged(List<PinnedKeyring> keyrings, List<PinnedRoot> roots) {
        return judged(keyrings, roots, null, new LinkedHashSet<>()).reason();
    }

    /** The good call's recorded time. */
    private static long recorded() {
        return good().get("recordedTs").get("last").asLong();
    }

    @Test
    void aMemberCountsForARecordNoLaterThanItsNotAfter() {
        long t = recorded();
        assertEquals(ReasonCode.OK, judged(List.of(new PinnedKeyring(keys(), t)), List.of(goodRoot(t))));
        assertEquals(ReasonCode.POLICY_EXPIRED,
                judged(List.of(new PinnedKeyring(keys(), t - 1)), List.of(goodRoot(t))));
        assertEquals(ReasonCode.POLICY_EXPIRED,
                judged(List.of(new PinnedKeyring(keys(), t)), List.of(goodRoot(t - 1))));
        // Beside a keyring that counts, one that has expired for the record gives no key.
        List<PinnedKeyring> rotation = List.of(new PinnedKeyring(rotated(), t), new PinnedKeyring(keys(), t - 1));
        assertEquals(ReasonCode.BAD_SIGNATURE, judged(rotation, List.of(goodRoot(t))));
        List<PinnedKeyring> renewed = new ArrayList<>(rotation);
        renewed.add(new PinnedKeyring(keys(), t));
        assertEquals(ReasonCode.OK, judged(renewed, List.of(goodRoot(t))));
        // And a root that has expired for it proves nothing, while one that counts does.
        List<PinnedKeyring> ring = List.of(new PinnedKeyring(keys(), t));
        List<PinnedRoot> roots = List.of(goodRoot(t - 1), secondRoot(t));
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, judged(ring, roots, null, new LinkedHashSet<>()).reason());
        String proof = second.proofFor(good().get("proofRoute").asText()).toJson();
        assertEquals(ReasonCode.OK, judged(ring, roots, proof, new LinkedHashSet<>()).reason());
    }

    @Test
    void noRootCountingForTheRecordIsPolicyExpired() {
        long t = recorded();
        List<PinnedKeyring> ring = List.of(new PinnedKeyring(keys(), Long.MAX_VALUE));
        List<PinnedRoot> lapsed = List.of(goodRoot(t - 1), secondRoot(0));
        Set<String> seen = new LinkedHashSet<>();
        OfflineResult expired = new OfflineResult(ReasonCode.POLICY_EXPIRED, "", "");
        assertEquals(expired, judged(ring, lapsed, null, seen));
        assertEquals(expired, judged(List.of(new PinnedKeyring(keys(), t - 1), new PinnedKeyring(rotated(), 0)),
                List.of(goodRoot(Long.MAX_VALUE)), null, seen));
        // Judged before check 1, so it names no one and spends no key, however malformed the chain.
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig b = VectorsV3Test.offlineConfig(c);
        assertEquals(expired, run(with(in, "\"x\"", in.recordedTs(), in.prompt(), in.nonceKey()),
                new OfflineConfig(ring, lapsed, b.allowedOrigins(), b.sess(), seen, null, null, null)));
        assertTrue(seen.isEmpty(), "no key spent");
    }

    @Test
    void aRecordWithNoTimeIsLeftToCheck7() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig b = VectorsV3Test.offlineConfig(c);
        OfflineConfig lapsed = new OfflineConfig(List.of(new PinnedKeyring(keys(), 0)), List.of(goodRoot(0)),
                b.allowedOrigins(), b.sess(), new LinkedHashSet<>(), null, null, null);
        assertEquals(ReasonCode.TIME_MISMATCH, run(with(in, in.stamps(), null, in.prompt(), in.nonceKey()), lapsed)
                .reason());
        // A record with a time is judged at it.
        assertEquals(ReasonCode.POLICY_EXPIRED, run(in, lapsed).reason());
    }

    /** A config pins at least one keyring and one root and no null member, refused when built. */
    @Test
    void aConfigRefusesNoMembersOrANullOne() {
        List<PinnedKeyring> ring = List.of(new PinnedKeyring(keys(), Long.MAX_VALUE));
        List<PinnedRoot> root = List.of(goodRoot(Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> config(List.of(), root));
        assertThrows(IllegalArgumentException.class, () -> config(ring, List.of()));
        assertThrows(NullPointerException.class, () -> config(null, root));
        assertThrows(NullPointerException.class, () -> config(ring, null));
        assertThrows(NullPointerException.class, () -> config(Arrays.asList(ring.get(0), null), root));
        assertThrows(NullPointerException.class, () -> config(ring, Arrays.asList(null, root.get(0))));
        List<PinnedKeyring> rings = new ArrayList<>(ring);
        OfflineConfig copied = config(rings, root);
        rings.clear();
        assertEquals(ring, copied.keyrings(), "copied in");
    }

    private static OfflineConfig config(List<PinnedKeyring> keyrings, List<PinnedRoot> roots) {
        return new OfflineConfig(keyrings, roots, Set.of("session"), "", new LinkedHashSet<>(), null, null, null);
    }
}
