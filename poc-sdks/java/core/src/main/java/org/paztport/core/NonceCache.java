// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * Replay guard keyed by an opaque string. {@link #seenBefore} atomically
 * records the key at {@code now} and reports whether it had been seen already.
 * What the key is made of belongs to the protocol version using the cache, so
 * the cache never has to understand it. A real deployment can swap in a shared,
 * expiring implementation.
 */
public interface NonceCache {

    /**
     * Records {@code key} at {@code now} (epoch milliseconds, from the
     * verifier's clock) and returns true if it was already recorded and has not
     * yet expired. A hit does not refresh the recorded time.
     */
    boolean seenBefore(String key, long now);

    /**
     * How long, in milliseconds, a recorded key is remembered. A verifier must
     * not accept a stamp older than this, or a replay could outlive its record.
     * {@link Long#MAX_VALUE} means keys are never forgotten.
     */
    long ttlMs();
}
