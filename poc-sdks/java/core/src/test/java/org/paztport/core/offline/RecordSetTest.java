// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paztport.core.offline.Handshake.ENTRY;
import static org.paztport.core.offline.Handshake.FAR;
import static org.paztport.core.offline.Handshake.NOW;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.Influence;
import org.paztport.core.policy.Keyring;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;

/**
 * verification.md §Offline verification: a recorded call counts in its session only up to the session's limits, and
 * replay is judged across the whole record set. The names are the TypeScript core's; this SDK has no local steps
 * (the MCP profile), so its record set holds only calls and responses. A recorded response is checked by the live
 * chain verifier at the time recorded, as {@code paztport-http}'s response check runs it.
 */
class RecordSetTest {

    private static final String NONCE_KEY = "rid-1|call-1|req";
    private static final String RESPONSE_KEY = "rid-1|call-1|resp";

    /** A two-stamp call chain in the handshake's session, its last stamp at {@code ts}, signed by its client keys. */
    private static String call(Handshake h, long ts) {
        Stamp origin = Stamp.sign("session", "pi-1", "rid-1", ts - 1, h.sess(), "pi", Bindings.prompt("p"), "",
                "", h.session.getPrivate());
        Stamp hop = Stamp.sign("pi", "pi-1", "rid-1", ts, h.sess(), "orders", "call-bind",
                Influence.commit(List.of()), origin.sig(), h.pi.getPrivate());
        return Chains.toJson(List.of(origin, hop));
    }

    /** The offline check of a call recorded in the handshake's session: the request's keyring and root, its id. */
    private static ReasonCode checkCall(Handshake h, String chain, long ts, Set<String> spent) {
        Keyring keyring = Keyring.of(Map.of("session", h.session.getPublic(), "pi", h.pi.getPublic()));
        return OfflineVerifier.verify(
                new OfflineInput(chain, "call-bind", "[]", h.clientTree.proofFor("session/pi/orders").toJson(),
                        "orders", true, NONCE_KEY, "rid-1", new RecordedTimes(ts, null), "p"),
                // The session's windows are judged by callInSession, so the members have none.
                new OfflineConfig(List.of(new PinnedKeyring(keyring, Long.MAX_VALUE)),
                        List.of(new PinnedRoot(h.clientTree.root(), "c1", Long.MAX_VALUE)), Set.of("session"), h.sess(),
                        spent, null, null, null)).reason();
    }

    // "The call counts in its session only up to the session's limits, judged at the last stamp's ts. A call that
    // otherwise verifies, in a session whose recorded handshake is attested, but whose last stamp's ts is past one
    // of the session's limits, is OUTSIDE_SESSION."
    @Test
    void aCallPastALimitIsOutsideSession() {
        Handshake h = Handshake.with(o -> o.cert = NOW);
        RecordedSession s = h.recorded();
        Map<Long, ReasonCode> want = Map.of(NOW - 1, ReasonCode.OK, NOW, ReasonCode.OK,
                NOW + 1, ReasonCode.OUTSIDE_SESSION);
        want.forEach((ts, code) -> {
            ReasonCode verified = checkCall(h, call(h, ts), ts, new RecordSet().spent());
            assertEquals(ReasonCode.OK, verified);
            assertEquals(code, RecordSet.callInSession(s, verified, ts), "at " + ts);
        });
    }

    @Test
    void aCallThatFailsKeepsItsOwnResult() {
        RecordedSession s = Handshake.with(o -> o.cert = NOW).recorded();
        assertEquals(ReasonCode.BAD_SIGNATURE, RecordSet.callInSession(s, ReasonCode.BAD_SIGNATURE, NOW + 1));
        assertEquals(ReasonCode.PATH_NOT_ALLOWED, RecordSet.callInSession(s, ReasonCode.PATH_NOT_ALLOWED, NOW + 1));
    }

    @Test
    void aSessionNotAttestedGivesNoResult() {
        Handshake h = Handshake.with(o -> o.status = "unsafe");
        assertNull(RecordSet.callInSession(h.recorded(), ReasonCode.OK, NOW));
    }

    // "The nonce key has not been spent anywhere in the record set (REPLAY)."
    @Test
    void callsShareOneSetOfSpentKeys() {
        Handshake h = Handshake.attested();
        RecordSet records = new RecordSet();
        assertEquals(ReasonCode.OK, checkCall(h, call(h, NOW), NOW, records.spent()));
        assertTrue(records.spent().contains(NONCE_KEY));
        // a copy recorded much later is still a replay: the set never forgets
        assertEquals(ReasonCode.REPLAY, checkCall(h, call(h, FAR), FAR, records.spent()));
    }

    @Test
    void aRepeatedSessionRecordResetsNeitherCache() {
        Handshake h = Handshake.attested();
        RecordSet records = new RecordSet();
        RecordedSession first = h.recorded();
        assertEquals(ReasonCode.OK,
                RecordSet.callInSession(first, checkCall(h, call(h, NOW), NOW, records.spent()), NOW));
        assertEquals(ReasonCode.OK,
                checkResponse(h, first.responseNotAfter().getAsLong(), records.responseNonces(), NOW));
        // the same handshake recorded again
        RecordedSession again = h.recorded();
        assertTrue(again.attested());
        assertEquals(ReasonCode.REPLAY,
                RecordSet.callInSession(again, checkCall(h, call(h, NOW), NOW, records.spent()), NOW));
        assertEquals(ReasonCode.REPLAY,
                checkResponse(h, again.responseNotAfter().getAsLong(), records.responseNonces(), NOW));
    }

    // "A recorded response: … one nonce cache that never forgets across the record set."
    @Test
    void theResponseCacheNeverForgets() {
        Handshake h = Handshake.attested();
        RecordSet records = new RecordSet();
        long limit = h.recorded().responseNotAfter().getAsLong();
        assertEquals(ReasonCode.OK, checkResponse(h, limit, records.responseNonces(), NOW));
        assertEquals(ReasonCode.REPLAY, checkResponse(h, limit, records.responseNonces(), NOW));
        // a live cache forgets a key after its TTL; this one still holds it at the end of time
        assertEquals(Long.MAX_VALUE, records.responseNonces().ttlMs());
        assertTrue(records.responseNonces().seenBefore(RESPONSE_KEY, Long.MAX_VALUE));
    }

    // "Check 0 runs at that time, with the policyNotAfter the client used … So a response recorded after the
    // server's material expired is POLICY_EXPIRED."
    @Test
    void aResponsePastTheServersMaterialIsPolicyExpired() {
        Handshake h = Handshake.with(o -> o.serverRoot = NOW + 10);
        long limit = h.recorded().responseNotAfter().getAsLong();
        assertEquals(ReasonCode.POLICY_EXPIRED, checkResponse(h, limit, new RecordSet().responseNonces(), NOW + 11));
        assertEquals(ReasonCode.OK, checkResponse(h, limit, new RecordSet().responseNonces(), NOW));
    }

    /**
     * The live check of the server's signed response to call-1, stamped at NOW, as recorded at {@code at}: the
     * reply's keyring and the server's root, the session's response limit, and the record set's response cache.
     */
    private static ReasonCode checkResponse(Handshake h, long policyNotAfter, NonceCache nonces, long at) {
        Stamp s0 = Stamp.sign(ENTRY, "e-1", "rid-1", NOW, h.sess(), "tools", "b0", "", "",
                h.entry.getPrivate());
        Stamp s1 = Stamp.sign("tools", "t-1", "rid-1", NOW, h.sess(), "pi", "response-bind",
                Influence.commit(List.of()), s0.sig(), h.entry.getPrivate());
        Keyring keyring = Keyring.of(Map.of(ENTRY, h.entry.getPublic(), "tools", h.entry.getPublic()));
        // The session's one keyring and root, each until the session's response limit.
        VerifierConfig cfg = new VerifierConfig(List.of(new PinnedKeyring(keyring, policyNotAfter)),
                List.of(new PinnedRoot(h.serverTree.root(), "s1", policyNotAfter)), policyNotAfter, Set.of(ENTRY),
                h.sess(), nonces, () -> at, VerifierConfig.CALL_MAX_AGE_MS, VerifierConfig.RUN_MAX_AGE_MS);
        return new Verifier(cfg).verify(new VerifyInput(Chains.toJson(List.of(s0, s1)), "response-bind", "[]",
                h.serverTree.proofFor("mcp-entry/tools").toJson(), "pi", false, RESPONSE_KEY, null)).reason();
    }
}
