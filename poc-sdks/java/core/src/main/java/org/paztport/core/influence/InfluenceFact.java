// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

/** What the public-write rule sees of one piece of context: its class, and whose it is (null when unknown). */
public record InfluenceFact(InfluenceClass cls, String owner) {
}
