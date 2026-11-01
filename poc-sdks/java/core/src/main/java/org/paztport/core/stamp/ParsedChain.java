// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.util.List;
import org.paztport.core.verify.ReasonCode;

/**
 * The outcome of reading a chain off the wire: the stamps, or the one reason the input was refused. A verifier
 * returns this instead of throwing, so malformed input is a typed rejection.
 */
public record ParsedChain(List<Stamp> stamps, ReasonCode failure) {

    public ParsedChain {
        stamps = List.copyOf(stamps);
    }

    static ParsedChain fail(ReasonCode code) {
        return new ParsedChain(List.of(), code);
    }

    public boolean ok() {
        return failure == null;
    }
}
