// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paztport.core.offline.Handshake.ENTRY;
import static org.paztport.core.offline.Handshake.FAR;
import static org.paztport.core.offline.Handshake.MAX_SAFE;
import static org.paztport.core.offline.Handshake.NOW;
import static org.paztport.core.offline.Handshake.inMember;
import static org.paztport.core.offline.Handshake.text;
import static org.paztport.core.offline.Handshake.with;
import static org.paztport.core.offline.Handshake.without;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

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
        assertFalse(Handshake.with(o -> o.status = "unsafe").recorded().attested());
        assertFalse(Handshake.recorded(h.request, h.reply, Handshake.key(Crypto.generateEd25519KeyPair()), ENTRY)
                .attested());
        assertFalse(Handshake.recorded(h.request, h.reply, h.pin, "tools").attested());
        String otherRootSig = SignedRoot.sign(h.clientTree.root(), "c1", FAR,
                Crypto.generateEd25519KeyPair().getPrivate()).sig();
        JsonValue.Obj badClientRoot = inMember(h.request, "clientRoot",
                r -> with(r, "sig", new JsonValue.Str(otherRootSig)));
        assertFalse(Handshake.recorded(badClientRoot, h.reply, h.pin, ENTRY).attested());
        String otherRingSig = KeyringFile.sign(Map.of("session", Handshake.key(h.session), "pi", Handshake.key(h.pi)),
                Handshake.key(h.clientPolicy), FAR, Crypto.generateEd25519KeyPair().getPrivate()).sig();
        JsonValue.Obj badRing = with(h.request, "clientKeyringSig", new JsonValue.Str(otherRingSig));
        assertFalse(Handshake.recorded(badRing, h.reply, h.pin, ENTRY).attested());
    }

    @Test
    void theEntryIsTheVerifiersNeverTheRecords() {
        Handshake h = Handshake.attested();
        assertTrue(Handshake.recorded(h.request, h.resigned(r -> r), h.pin, ENTRY).attested());
        assertFalse(Handshake.recorded(h.request, h.resigned(r -> r), h.pin, "tools").attested());
        // a reply has no member naming an entry: one signed with it is not a reply, and opened no attested session
        assertFalse(Handshake.recorded(h.request, h.resigned(r -> with(r, "serverEntry", new JsonValue.Str(ENTRY))),
                h.pin, ENTRY).attested());
    }

    @Test
    void aRequestWithNoKeyringSignatureIsNotAttested() {
        Handshake h = Handshake.attested();
        assertFalse(Handshake.recorded(without(h.request, "clientKeyringSig"), h.reply, h.pin, ENTRY).attested());
    }

    // "The handshake record carries no signed time, so it is judged at each call's recorded time … One session can
    // therefore be attested for the calls recorded up to its limits and not for those after them."
    // "Its limits are the certificate's notAfter (entry-key form) and the notAfter of each root and keyring, the
    // client's and the server's."
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
        assertFalse(Handshake.recorded(with(h.request, "clientKeyringNotAfter", new JsonValue.Int(0)), h.reply, h.pin,
                ENTRY).attested());
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
        // 2^53 - 1 when the reply holds neither window, as a policy-key reply with no root does
        Handshake p = Handshake.with(o -> o.policyKeyForm = true);
        RecordedSession rootless = Handshake.recorded(p.request, with(p.reply, "serverRoot", new JsonValue.Null()),
                p.pin, ENTRY);
        assertFalse(rootless.attested());
        assertEquals(MAX_SAFE, rootless.responseNotAfter());
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
                RecordedSession.of("not a request", text(h.reply), h.pin, ENTRY).responseNotAfter());
    }

    // "There is no client pin offline. The server's signed "attested" reply … is its statement that it pinned them."
    @Test
    void thereIsNoClientPinOffline() {
        // nothing the verifier is given names the client policy key: the reply alone vouches for it
        Handshake h = Handshake.attested();
        assertTrue(RecordedSession.of(text(h.request), text(h.reply), h.pin, ENTRY).attested());
    }

    // "A recorded request that is not a well-formed request … opened no attested session": a request is read from its
    // bytes as wire bytes, so the same request in another member order is not one.
    @Test
    void aRequestInWireMemberOrderIsNotAttested() {
        Handshake h = Handshake.attested();
        String request = text(h.request);
        int nonce = request.lastIndexOf(",\"nonce\":");
        String nonceFirst = "{" + request.substring(nonce + 1, request.length() - 1) + ","
                + request.substring(1, nonce) + "}";

        assertTrue(RecordedSession.of(request, text(h.reply), h.pin, ENTRY).attested());
        assertFalse(RecordedSession.of(nonceFirst, text(h.reply), h.pin, ENTRY).attested());
    }

    // "A root or keyring is judged at the record's time, on both sides, as above, but only after its own signature
    // has verified … so one moved in the record fails its signature offline too … One dropped from the record leaves
    // a root or keyring without a window, which a reader refuses, so the handshake opened no attested session."
    @Test
    void aMovedWindowFailsItsSignatureAndADroppedOneIsRefused() {
        Handshake h = Handshake.with(o -> o.clientRoot = NOW);
        JsonValue.Obj moved = inMember(h.request, "clientRoot", r -> with(r, "notAfter", new JsonValue.Int(FAR)));
        assertFalse(Handshake.recorded(moved, h.reply, h.pin, ENTRY).attested());
        Handshake g = Handshake.attested();
        JsonValue.Obj ringMoved = g.resigned(r -> with(r, "serverKeyringNotAfter", new JsonValue.Int(FAR + 1)));
        assertFalse(Handshake.recorded(g.request, ringMoved, g.pin, ENTRY).attested());

        JsonValue.Obj dropped = inMember(h.request, "clientRoot", r -> without(r, "notAfter"));
        JsonValue.Obj ringDropped = without(g.request, "clientKeyringNotAfter");
        for (JsonValue.Obj request : List.of(dropped, ringDropped)) {
            assertThrows(IllegalArgumentException.class, () -> SessionRequest.parse(text(request)));
        }
        assertFalse(Handshake.recorded(dropped, h.reply, h.pin, ENTRY).attested());
        assertFalse(Handshake.recorded(ringDropped, g.reply, g.pin, ENTRY).attested());
        JsonValue.Obj rootDropped = g.resigned(r -> inMember(r, "serverRoot", root -> without(root, "notAfter")));
        assertEquals(ReplyCheck.MALFORMED_REPLY,
                Sessions.checkReply(text(rootDropped), SessionRequest.parse(text(g.request)), g.pin, ENTRY, NOW));
        assertFalse(Handshake.recorded(g.request, rootDropped, g.pin, ENTRY).attested());
    }

    // The session id calls are checked against is the one in the reply this session judged.
    @Test
    void theSessionIdIsTheJudgedReplys() {
        Handshake h = Handshake.attested();
        assertEquals(((JsonValue.Str) h.reply.get("sess")).value(), h.recorded().sess());
        // read whether or not the session is attested; the reader relies on it only when it is
        Handshake unsafe = Handshake.with(o -> o.status = "unsafe");
        assertEquals(unsafe.sess(), unsafe.recorded().sess());
        assertNull(Handshake.recorded(h.request, h.resigned(r -> with(r, "sess", new JsonValue.Int(7))), h.pin, ENTRY)
                .sess());
        assertNull(Handshake.recorded(h.request, h.resigned(r -> without(r, "sess")), h.pin, ENTRY).sess());
        assertNull(RecordedSession.of(text(h.request), "{", h.pin, ENTRY).sess());
    }

    @Test
    void neverThrows() {
        Handshake h = Handshake.attested();
        String request = text(h.request);
        String reply = text(h.reply);
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
            }
        assertEquals(MAX_SAFE, RecordedSession.of(null, null, null, null).responseNotAfter());
    }
}
