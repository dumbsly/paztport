// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.HashSet;
import java.util.Set;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.ReasonCode;

/**
 * One record set's replay state (verification.md &sect;Offline verification, check 10), and the limit a recorded
 * session sets on the calls made in it. The nonce keys its calls spend are one set for the whole record set, passed
 * as {@link OfflineConfig#seen} to every call checked in it, and its responses share one nonce cache that never
 * forgets: a live cache forgets a key after its window, which offline would let a copy pass once a later record is
 * far enough on. Nothing in a session record resets either, so a repeated handshake leaves them as they are. A
 * record set is read in order, by one thread.
 */
public final class RecordSet {

    private final Set<String> spent = new HashSet<>();
    private final NonceCache responseNonces = new InMemoryNonceCache();

    /** An empty record set: no nonce key spent yet. */
    public RecordSet() {
    }

    /** The nonce keys spent so far by the record set's calls; the offline verifier adds each call's own. */
    public Set<String> spent() {
        return spent;
    }

    /** The nonce cache every response in the record set is checked against; it never forgets a key. */
    public NonceCache responseNonces() {
        return responseNonces;
    }

    /**
     * A recorded call's result in its session (verification.md &sect;Offline verification): {@code OUTSIDE_SESSION}
     * when the call otherwise verifies ({@code reason} is OK) but its last stamp's {@code ts}, {@code at}, is past
     * one of the session's limits; else {@code reason}. Null for a session that is not attested at all: the spec
     * gives a call relying on one no result, so the record set's reader reports it.
     */
    public static ReasonCode callInSession(RecordedSession session, ReasonCode reason, long at) {
        if (!session.attested()) {
            return null;
        }
        return reason == ReasonCode.OK && !session.attestedAt(at) ? ReasonCode.OUTSIDE_SESSION : reason;
    }
}
