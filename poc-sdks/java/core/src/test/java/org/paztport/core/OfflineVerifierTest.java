// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.offline.OfflineConfig;
import org.paztport.core.offline.OfflineInput;
import org.paztport.core.offline.OfflineResult;
import org.paztport.core.offline.OfflineVerifier;
import org.paztport.core.offline.RecordedTimes;
import org.paztport.core.offline.Signers;
import org.paztport.core.stamp.Chains;
import org.paztport.core.verify.ReasonCode;

/** Offline-only behaviour the vectors do not pin: totality, the optional inputs and the age-limit pair. */
class OfflineVerifierTest {

    @BeforeAll
    static void load() throws IOException {
        VectorsV3Test.load();
    }

    private static JsonNode good() {
        return VectorsV3Test.offlineCase("recorded call");
    }

    private static OfflineResult run(OfflineInput in, OfflineConfig cfg) {
        return OfflineVerifier.verify(in, cfg);
    }

    private static OfflineConfig cfg(JsonNode c, Long runMax, Long callMax, Signers signers) {
        OfflineConfig b = VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c));
        return new OfflineConfig(b.keyring(), b.root(), b.rootId(), b.allowedOrigins(), b.sess(), b.seen(), signers,
                runMax, callMax);
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
                VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c)));
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
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.CHAIN_MISSING, run(with(in, "\"x\"", in.recordedTs(), in.prompt(),
                in.nonceKey()), cfg).reason());
        assertEquals(ReasonCode.CHAIN_MISSING, run(null, cfg).reason());
    }

    @Test
    void noRecordedTimesComparesNoTime() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.OK,
                run(with(in, in.stamps(), null, in.prompt(), in.nonceKey()), VectorsV3Test.offlineConfig(c,
                        VectorsV3Test.policy(c))).reason());
    }

    @Test
    void theRunsRecordedStartTimesMustIncludeTheOrigins() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        long last = in.recordedTs().last();
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.TIME_MISMATCH, run(with(in, in.stamps(), new RecordedTimes(last, Set.of(1L)),
                in.prompt(), in.nonceKey()), cfg).reason());
        long origin = c.get("chain").get(0).get("ts").asLong();
        assertEquals(ReasonCode.OK, run(with(in, in.stamps(), new RecordedTimes(last, Set.of(origin)),
                in.prompt(), "k2"), cfg).reason());
    }

    @Test
    void oneAgeLimitAloneFailsClosed() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.EXPIRED, run(in, cfg(c, 1_800_000L, null, null)).reason());
        assertEquals(ReasonCode.EXPIRED, run(in, cfg(c, null, 5000L, null)).reason());
        assertEquals(ReasonCode.OK, run(in, cfg(c, null, null, null)).reason());
    }

    @Test
    void noPromptCanNeverBeBound() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.PROMPT_MISMATCH, run(with(in, in.stamps(), in.recordedTs(), null, in.nonceKey()),
                VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c))).reason());
    }

    @Test
    void aSpentNonceIsRecordedAndRefusedOnTheSecondUse() {
        JsonNode c = good();
        OfflineInput in = VectorsV3Test.offlineInput(c, VectorsV3Test.policy(c));
        OfflineConfig cfg = VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c));
        assertEquals(ReasonCode.OK, run(in, cfg).reason());
        assertTrue(cfg.seen().contains(in.nonceKey()));
        assertEquals(ReasonCode.REPLAY, run(in, cfg).reason());
        OfflineInput none = with(in, in.stamps(), in.recordedTs(), in.prompt(), null);
        assertEquals(ReasonCode.REPLAY, run(none, VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c))).reason());
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
                    VectorsV3Test.offlineConfig(c, VectorsV3Test.policy(c))).reason());
        }
    }
}
