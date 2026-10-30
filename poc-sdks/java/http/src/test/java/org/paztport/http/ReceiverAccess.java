// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.VerifyResult;

/**
 * Test access to the receiver's trace line, which {@link HttpReceiver} keeps package-private. The starter's tests pin
 * the request line beside the egress's boundary line, which is still the starter's, so this lives in the receiver's
 * package for that reason only.
 */
public final class ReceiverAccess {

    private ReceiverAccess() {
    }

    /** The {@code PAZTPORT_TRACE request} line for one verification. */
    public static String traceLine(String rid, VerifyResult result, String receiver, Peer peer,
            List<InfluenceEntry> influence) {
        return HttpReceiver.traceLine(rid, result, receiver, peer, influence);
    }
}
