// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Collection;

/** The one standing influence rule, for every public destination. */
public final class InfluenceRule {

    private InfluenceRule() {
    }

    /**
     * A write is refused when the context holds untrusted content (third-party, or local-untrusted, which counts
     * as such) and private content that is not the destination owner's. A null or empty owner, on a private fact
     * or on the destination, is unknown and fails closed. The caller takes {@code destinationOwner} from trusted
     * records, never from content.
     */
    public static boolean publicWriteRefused(Collection<InfluenceFact> influence, String destinationOwner) {
        boolean untrusted = influence.stream()
                .anyMatch(f -> f.cls() == InfluenceClass.THIRD_PARTY || f.cls() == InfluenceClass.LOCAL_UNTRUSTED);
        if (!untrusted) {
            return false;
        }
        boolean destinationUnknown = destinationOwner == null || destinationOwner.isEmpty();
        return influence.stream().anyMatch(f -> f.cls() == InfluenceClass.PRIVATE
                && (f.owner() == null || f.owner().isEmpty() || destinationUnknown
                        || !f.owner().equals(destinationOwner)));
    }
}
