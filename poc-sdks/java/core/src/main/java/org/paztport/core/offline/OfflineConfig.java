// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.List;
import java.util.Set;
import org.paztport.core.internal.ChainChecks;
import org.paztport.core.verify.PinnedKeyring;
import org.paztport.core.verify.PinnedRoot;
import org.paztport.core.verify.VerifierConfig;

/**
 * What the offline verifier pins. Its keyrings and roots, one or more of each, count for a record when its recorded
 * time is at most their {@code notAfter}; a member whose window its record kind judges itself, as a recorded
 * session's are, has {@link Long#MAX_VALUE}, no window, and counts for every record. Both lists are copied, and an
 * empty one, or a null member, is refused here. {@code seen} is every nonce key spent so far anywhere in the record
 * set; a chain that reaches the replay check adds its own, so the set is mutated. {@code signers}, when non-null, is
 * for a chain that never leaves one process. The age limits need no clock: for a chain the live verifier checked at
 * its last stamp's time, the last stamp is at most {@code runMaxAgeMs} after the origin and the origin at most
 * {@code callMaxAgeMs} after the last stamp. A limit left null is its live default
 * ({@link VerifierConfig#RUN_MAX_AGE_MS}, {@link VerifierConfig#CALL_MAX_AGE_MS}), each independently, so no
 * configuration leaves a chain's age unlimited.
 */
public record OfflineConfig(
        List<PinnedKeyring> keyrings,
        List<PinnedRoot> roots,
        Set<String> allowedOrigins,
        String sess,
        Set<String> seen,
        Signers signers,
        Long runMaxAgeMs,
        Long callMaxAgeMs) {

    public OfflineConfig {
        keyrings = ChainChecks.members(keyrings, "keyrings");
        roots = ChainChecks.members(roots, "roots");
    }
}
