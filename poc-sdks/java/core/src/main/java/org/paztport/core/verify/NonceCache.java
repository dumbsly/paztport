// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

/**
 * Replay guard keyed by an opaque string. {@link #seenBefore} atomically
 * records the key at {@code now} and reports whether it had been seen already.
 * What the key is made of belongs to the protocol version using the cache, so
 * the cache never has to understand it. A deployment that wants one cache across its replicas can supply a
 * shared, expiring implementation.
 *
 * <p>A cache that cannot answer (a shared store that is down or too slow) throws an unchecked exception from
 * {@link #seenBefore}. It must not answer "unseen" instead, which would let a replay through. The verifier wraps
 * whatever {@link RuntimeException} the cache throws in {@link NonceCacheUnavailableException}, and the host
 * decides what the request then gets. The verifier takes no timeout, so the cache owns its own and throws when it
 * is reached.
 */
public interface NonceCache {

    /**
     * Records {@code key} at {@code now} (epoch milliseconds, from the
     * verifier's clock) and returns true if it was already recorded and has not
     * yet expired. A hit does not refresh the recorded time.
     *
     * @throws RuntimeException when the cache cannot answer
     */
    boolean seenBefore(String key, long now);

    /**
     * How long, in milliseconds, a recorded key is remembered. A verifier must
     * not accept a stamp older than this, or a replay could outlive its record.
     * {@link Long#MAX_VALUE} means keys are never forgotten.
     */
    long ttlMs();
}
