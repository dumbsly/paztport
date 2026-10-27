// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Set;

/**
 * The times a record set gives for a chain. {@code last} is when the chain's last hop made it, as recorded beside
 * it: the last stamp's {@code ts} must be this. {@code run}, null when the run has no records, holds the start
 * times it gives: the origin's {@code ts} must be one of them.
 */
public record RecordedTimes(long last, Set<Long> run) {
}
