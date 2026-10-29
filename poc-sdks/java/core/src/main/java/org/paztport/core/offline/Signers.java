// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.List;
import java.util.Objects;

/**
 * The services that sign a chain that never leaves one process, in order, and the instance they all report.
 * For the offline verifier, which re-checks a recorded chain (a client's local steps, say) whose signers it knows.
 */
public record Signers(List<String> svcs, String inst) {

    public Signers {
        svcs = List.copyOf(svcs);
        Objects.requireNonNull(inst, "inst");
    }
}
