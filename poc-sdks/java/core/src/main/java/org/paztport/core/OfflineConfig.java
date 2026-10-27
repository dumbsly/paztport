// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Set;

/**
 * What the offline verifier pins. {@code seen} is every nonce key spent so far anywhere in the record set; a
 * chain that reaches the replay check adds its own, so the set is mutated. {@code signers}, when non-null,
 * is for a chain that never leaves one process. The age limits need no clock: for a chain the live verifier
 * checked at its last stamp's time, the last stamp is at most {@code runMaxAgeMs} after the origin and the origin
 * at most {@code callMaxAgeMs} after the last stamp. Both null leaves the chain's age unlimited; one alone is
 * a misconfiguration and fails closed as EXPIRED.
 */
public record OfflineConfig(
        Keyring keyring,
        byte[] root,
        String rootId,
        Set<String> allowedOrigins,
        String sess,
        Set<String> seen,
        Signers signers,
        Long runMaxAgeMs,
        Long callMaxAgeMs) {
}
