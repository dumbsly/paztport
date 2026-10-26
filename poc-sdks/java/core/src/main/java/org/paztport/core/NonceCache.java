// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * Replay guard keyed by {@code (rid, svc)}. {@link #seenBefore} atomically
 * records the pair and reports whether it had been seen already. A real
 * deployment can swap in a shared, expiring implementation.
 */
public interface NonceCache {

    boolean seenBefore(String rid, String svc);
}
