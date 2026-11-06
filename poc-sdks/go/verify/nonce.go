// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"sync"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
)

// NonceCache is a replay cache, keyed by an opaque string. What a key is made of belongs to the protocol
// (a request's rid, the hop and the direction), so a cache never has to understand it.
type NonceCache interface {
	// SeenBefore records key at now, in milliseconds since the Unix epoch, and reports whether it was
	// already recorded and is still remembered. A hit does not refresh the recorded time. A cache that
	// can block, such as one backed by a store, honours ctx's cancellation and deadline. The error is for
	// a cache that could not answer, such as one whose store is down or whose ctx is done; the verifier
	// then answers with the error, not a verdict. At a receiver, enforce refuses the request with 503
	// and audit or no mode serves it unverified and unattested; neither treats it as a replay.
	SeenBefore(ctx context.Context, key string, now int64) (bool, error)
	// TTL returns how long, in milliseconds, the cache remembers a key. A verifier refuses every key when
	// it is less than twice its call window, since a replay could outlive its record.
	TTL() int64
}

// MemoryNonceCache is a NonceCache held in the process's memory, safe for use by many goroutines. A key
// is remembered while now - recorded is at most the TTL, and forgotten after; a key offered again once
// forgotten is recorded afresh. The zero MemoryNonceCache remembers a key for 0 ms.
type MemoryNonceCache struct {
	ttl int64

	mu    sync.Mutex
	seen  map[string]int64 // each remembered key's recorded time
	order []record         // the keys in the order they were recorded, so the oldest are dropped first
}

// record is a key and the time it was recorded.
type record struct {
	key string
	at  int64
}

// NewMemoryNonceCache returns an empty cache that remembers each key for ttlMs milliseconds.
func NewMemoryNonceCache(ttlMs int64) *MemoryNonceCache {
	return &MemoryNonceCache{ttl: ttlMs}
}

// SeenBefore implements NonceCache. It never blocks, so it ignores ctx, and it never fails.
//
// It also drops the keys it has forgotten, oldest first, stopping at the first it still remembers: with
// a clock that steps back, a forgotten key recorded after a remembered one is held in memory until that
// one goes, but it is never a hit.
func (c *MemoryNonceCache) SeenBefore(_ context.Context, key string, now int64) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[string]int64)
	}
	at, ok := c.seen[key]
	hit := ok && exact.AtMost(now, at, c.ttl)
	if !hit {
		c.seen[key] = now
		c.order = append(c.order, record{key, now})
	}
	for len(c.order) > 0 && !exact.AtMost(now, c.order[0].at, c.ttl) {
		// A key recorded afresh has a later record of its own, so only its latest record drops it.
		if r := c.order[0]; c.seen[r.key] == r.at {
			delete(c.seen, r.key)
		}
		c.order[0] = record{}
		c.order = c.order[1:]
	}
	return hit, nil
}

// TTL implements NonceCache.
func (c *MemoryNonceCache) TTL() int64 {
	return c.ttl
}
