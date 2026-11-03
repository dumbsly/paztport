// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import java.util.Objects;
import org.paztport.core.policy.Keyring;

/**
 * A keyring a verifier pins, already verified against its policy key, and its {@code notAfter} (milliseconds since
 * the epoch, inclusive). Live, it is used while the clock is at most {@code notAfter}; offline, for a record whose
 * recorded time is at most it, and {@link Long#MAX_VALUE} is no window, for a record kind that judges the keyring's
 * window itself. Any other window outside [0, 2^53 &minus; 1] is current at no time, as no signed keyring carries
 * one.
 */
public record PinnedKeyring(Keyring keys, long notAfter) {

    public PinnedKeyring {
        Objects.requireNonNull(keys, "keys");
    }
}
