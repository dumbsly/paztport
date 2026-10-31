// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paztport.core.offline.Handshake.ENTRY;
import static org.paztport.core.offline.Handshake.FAR;
import static org.paztport.core.offline.Handshake.MAX_SAFE;
import static org.paztport.core.offline.Handshake.NOW;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * One test per sentence of sessions-and-influence.md §Recorded handshakes, and of verification.md §Offline
 * verification's recorded handshake; the names are the TypeScript core's.
 */
class RecordedSessionTest {

    // "Offline, a recorded handshake opened an attested session only when the reply's status is "attested", the
    // reply passes the client's check against the recorded pin and the server's entry service from the verifier's
    // own configuration, both roots verify against their sides' policy keys, and the keyring signature verifies."
    @Test
    void attestedOnlyWhenEveryCheckHolds() {
        Handshake h = Handshake.attested();
        RecordedSession s = h.recorded();
        assertTrue(s.attested());
        assertFalse(s.legacy());
        assertFalse(Handshake.with(o -> o.status = "unsafe").recorded().attested());
        assertFalse(Handshake.recorded(h.request, h.reply, Handshake.key(Crypto.generateEd25519KeyPair()), ENTRY)
                .attested());
        assertFalse(Handshake.recorded(h.request, h.reply, h.pin, "tools").attested());
        String otherRootSig = SignedRoot.sign(h.clientTree.root(), "c1", FAR,
                Crypto.generateEd25519KeyPair().getPrivate()).sig();
        ObjectNode badClientRoot = h.request(r -> ((ObjectNode) r.get("clientRoot")).put("sig", otherRootSig));
        assertFalse(Handshake.recorded(badClientRoot, h.reply, h.pin, ENTRY).attested());
        String otherRingSig = KeyringFile.sign(Map.of("session", Handshake.key(h.session), "pi", Handshake.key(h.pi)),
                Handshake.key(h.clientPolicy), FAR, Crypto.generateEd25519KeyPair().getPrivate()).sig();
        ObjectNode badRing = h.request(r -> r.put("clientKeyringSig", otherRingSig));
        assertFalse(Handshake.recorded(badRing, h.reply, h.pin, ENTRY).attested());
    }

    @Test
    void theEntryIsTheVerifiersNeverTheRecords() {
        Handshake h = Handshake.attested();
        assertTrue(Handshake.recorded(h.request, h.resigned(r -> r.put("serverEntry", "tools")), h.pin, ENTRY)
                .attested());
        assertFalse(Handshake.recorded(h.request, h.resigned(r -> { }), h.pin, "tools").attested());
    }

    // "When the request has no clientKeyringSig field at all, it is legacy: the keyring check is skipped, and the
    // result is marked legacy."
    @Test
    void aRequestWithNoKeyringSignatureIsLegacy() {
        Handshake h = Handshake.with(o -> o.legacy = true);
        assertTrue(h.recorded().attested());
        assertTrue(h.recorded().legacy());
        // a failure is never marked
        RecordedSession otherPin =
                Handshake.recorded(h.request, h.reply, Handshake.key(Crypto.generateEd25519KeyPair()), ENTRY);
        assertFalse(otherPin.attested());
        assertFalse(otherPin.legacy());
        // nothing signs a legacy request's keyring window
        assertFalse(Handshake.recorded(h.request(r -> r.put("clientKeyringNotAfter", FAR)), h.reply, h.pin, ENTRY)
                .attested());
    }

    // "The handshake record carries no signed time, so it is judged at each call's recorded time … One session can
    // therefore be attested for the calls recorded up to its limits and not for those after them."
    // "Its limits are the certificate's notAfter (entry-key form) and the notAfter of each root and keyring in the
    // new form, the client's and the server's."
    @ParameterizedTest
    @ValueSource(strings = {"cert", "clientRoot", "clientKeyring", "serverRoot", "serverKeyring"})
    void attestedUpToTheWindow(String which) {
        RecordedSession s = Handshake.with(window(which, NOW)).recorded();
        assertTrue(s.attestedAt(NOW - 1));
        assertTrue(s.attestedAt(NOW));
        assertFalse(s.attestedAt(NOW + 1));
        assertTrue(s.attested());
    }

    private static Consumer<Handshake.Options> window(String which, long notAfter) {
        return o -> {
            switch (which) {
                case "cert" -> o.cert = notAfter;
                case "clientRoot" -> o.clientRoot = notAfter;
                case "clientKeyring" -> o.clientKeyring = notAfter;
                case "serverRoot" -> o.serverRoot = notAfter;
                case "serverKeyring" -> o.serverKeyring = notAfter;
                default -> throw new IllegalArgumentException(which);
            }
        };
    }

    // "A verifier asking whether the session was attested at all judges it at the earliest of those, since each is
    // an upper bound."
    @Test
    void attestedAtAllIsJudgedAtTheEarliestLimit() {
        RecordedSession s = Handshake.with(o -> {
            o.cert = NOW + 5;
            o.clientRoot = NOW + 3;
            o.serverKeyring = NOW + 4;
        }).recorded();
        assertTrue(s.attested());
        assertTrue(s.attestedAt(NOW + 3));
        assertFalse(s.attestedAt(NOW + 4));
        // a window moved earlier in the record fails its signature at the earliest limit, so the session is
        // attested at no time
        Handshake h = Handshake.attested();
        assertFalse(Handshake.recorded(h.request(r -> r.put("clientKeyringNotAfter", 0)), h.reply, h.pin, ENTRY)
                .attested());
    }

    // "A policy-key reply over old-form material has no limit, and is judged the same at any time."
    @Test
    void aPolicyKeyReplyOverOldFormMaterialHasNoLimit() {
        RecordedSession s = Handshake.with(o -> {
            o.policyKeyForm = true;
            o.clientRoot = null;
            o.clientKeyring = null;
            o.serverRoot = null;
            o.serverKeyring = null;
        }).recorded();
        assertTrue(s.attested());
        assertTrue(s.attestedAt(0));
        assertTrue(s.attestedAt(MAX_SAFE));
    }

    // "A recorded response is limited only by the server's root window and, in the entry-key form, the server
    // keyring's: the client's windows and the certificate do not limit it."
    @Test
    void aResponseIsLimitedOnlyByTheServersRootAndEntryKeyKeyring() {
        assertEquals(NOW + 1, Handshake.with(o -> {
            o.serverRoot = NOW + 2;
            o.serverKeyring = NOW + 1;
        }).recorded().responseNotAfter());
        assertEquals(NOW + 1, Handshake.with(o -> {
            o.serverRoot = NOW + 1;
            o.serverKeyring = NOW + 2;
        }).recorded().responseNotAfter());
        assertEquals(FAR, Handshake.with(o -> {
            o.cert = NOW;
            o.clientRoot = NOW;
            o.clientKeyring = NOW;
        }).recorded().responseNotAfter());
        // the policy-key form carries no keyring signature, so no keyring window
        assertEquals(NOW + 2, Handshake.with(o -> {
            o.policyKeyForm = true;
            o.serverRoot = NOW + 2;
        }).recorded().responseNotAfter());
        // an old-form root or keyring sets no limit: 2^53 - 1 when neither has a window
        assertEquals(MAX_SAFE, Handshake.with(o -> {
            o.serverRoot = null;
            o.serverKeyring = null;
        }).recorded().responseNotAfter());
        assertEquals(NOW, Handshake.with(o -> {
            o.serverRoot = null;
            o.serverKeyring = NOW;
        }).recorded().responseNotAfter());
    }

    // The response limit is read from the reply's windows whether or not the session is attested, as the vectors
    // pin it; a reader gives a response in a session that is not attested no result.
    @Test
    void theResponseLimitIsReadWhetherOrNotTheSessionIsAttested() {
        RecordedSession unsafe = Handshake.with(o -> {
            o.status = "unsafe";
            o.serverRoot = NOW + 2;
        }).recorded();
        assertFalse(unsafe.attested());
        assertEquals(NOW + 2, unsafe.responseNotAfter());
        Handshake h = Handshake.with(o -> o.serverKeyring = NOW + 1);
        RecordedSession otherEntry = Handshake.recorded(h.request, h.reply, h.pin, "tools");
        assertFalse(otherEntry.attested());
        assertEquals(NOW + 1, otherEntry.responseNotAfter());
        assertEquals(NOW + 1,
                RecordedSession.of("not a request", h.reply.toString(), h.pin, ENTRY).responseNotAfter());
    }

    // "There is no client pin offline. The server's signed "attested" reply … is its statement that it pinned them."
    @Test
    void thereIsNoClientPinOffline() {
        // nothing the verifier is given names the client policy key: the reply alone vouches for it
        Handshake h = Handshake.attested();
        assertTrue(RecordedSession.of(h.request.toString(), h.reply.toString(), h.pin, ENTRY).attested());
    }

    // "Offline, a root or keyring in the old form is accepted, as recorded evidence holds it: it sets no limit, and
    // the session is not marked legacy for it (only a request with no clientKeyringSig is)."
    @Test
    void oldFormMaterialIsAcceptedSetsNoLimitAndIsNotLegacy() {
        RecordedSession s = Handshake.with(o -> {
            o.clientRoot = null;
            o.clientKeyring = null;
            o.serverRoot = null;
            o.serverKeyring = null;
        }).recorded();
        assertTrue(s.attested());
        assertFalse(s.legacy());
        // only the certificate limits it
        assertTrue(s.attestedAt(FAR));
        assertFalse(s.attestedAt(FAR + 1));
    }

    // "A root or keyring in the new form is judged at the record's time, on both sides, as above, but only after its
    // own signature has verified … so one moved or dropped in the record fails offline too."
    @Test
    void aMovedOrDroppedWindowFailsItsSignature() {
        Handshake h = Handshake.with(o -> o.clientRoot = NOW);
        ObjectNode moved = h.request(r -> ((ObjectNode) r.get("clientRoot")).put("notAfter", FAR));
        assertFalse(Handshake.recorded(moved, h.reply, h.pin, ENTRY).attested());
        ObjectNode dropped = h.request(r -> ((ObjectNode) r.get("clientRoot")).remove("notAfter"));
        assertFalse(Handshake.recorded(dropped, h.reply, h.pin, ENTRY).attested());
        Handshake g = Handshake.attested();
        assertFalse(Handshake.recorded(g.request, g.resigned(r -> r.put("serverKeyringNotAfter", FAR + 1)), g.pin,
                ENTRY).attested());
        ObjectNode ringDropped = g.request(r -> r.remove("clientKeyringNotAfter"));
        assertFalse(Handshake.recorded(ringDropped, g.reply, g.pin, ENTRY).attested());
    }

    // The session id calls are checked against is the one in the reply this session judged.
    @Test
    void theSessionIdIsTheJudgedReplys() {
        Handshake h = Handshake.attested();
        assertEquals(h.reply.get("sess").textValue(), h.recorded().sess());
        // read whether or not the session is attested; the reader relies on it only when it is
        Handshake unsafe = Handshake.with(o -> o.status = "unsafe");
        assertEquals(unsafe.sess(), unsafe.recorded().sess());
        assertNull(Handshake.recorded(h.request, h.resigned(r -> r.put("sess", 7)), h.pin, ENTRY).sess());
        assertNull(Handshake.recorded(h.request, h.resigned(r -> r.remove("sess")), h.pin, ENTRY).sess());
        assertNull(RecordedSession.of(h.request.toString(), "{", h.pin, ENTRY).sess());
    }

    @Test
    void neverThrows() {
        Handshake h = Handshake.attested();
        String request = h.request.toString();
        String reply = h.reply.toString();
        for (RecordedSession s : new RecordedSession[] {
            RecordedSession.of(request, null, h.pin, ENTRY),
            RecordedSession.of(request, "null", h.pin, ENTRY),
            RecordedSession.of(request, "{", h.pin, ENTRY),
            RecordedSession.of(null, reply, h.pin, ENTRY),
            RecordedSession.of("[]", reply, h.pin, ENTRY),
            RecordedSession.of(request, reply, null, ENTRY),
            RecordedSession.of(request, reply, h.pin, null),
            RecordedSession.of(null, null, null, null)}) {
            assertFalse(s.attested());
            assertFalse(s.attestedAt(NOW));
            assertFalse(s.legacy());
        }
        assertEquals(MAX_SAFE, RecordedSession.of(null, null, null, null).responseNotAfter());
    }
}
