// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"math"
	"sync"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// offer offers key to c at at, and expects want.
func offer(t *testing.T, c verify.NonceCache, key string, at int64, want bool) {
	t.Helper()
	got, err := c.SeenBefore(t.Context(), key, at)
	if err != nil {
		t.Fatalf("SeenBefore(%q, %d): %v", key, at, err)
	}
	if got != want {
		t.Fatalf("SeenBefore(%q, %d) = %t, want %t", key, at, got, want)
	}
}

// TestMemoryNonceCache pins the cache's memory: a key is a hit while now - recorded is at most the TTL,
// a hit does not refresh the recorded time, and a forgotten key is recorded afresh.
func TestMemoryNonceCache(t *testing.T) {
	c := verify.NewMemoryNonceCache(15)
	if c.TTL() != 15 {
		t.Fatalf("TTL() = %d, want 15", c.TTL())
	}
	offer(t, c, "a", 100, false)
	offer(t, c, "a", 100, true)
	offer(t, c, "b", 100, false)
	offer(t, c, "a", 110, true) // a hit, which does not move a's time from 100
	offer(t, c, "a", 115, true) // 15 ms after it was recorded: still remembered
	offer(t, c, "a", 116, false)
	offer(t, c, "a", 131, true) // recorded afresh at 116
	offer(t, c, "a", 132, false)
	offer(t, c, "b", 132, false)
}

// TestMemoryNonceCacheClockStepsBack checks that a key offered before the time it was recorded is
// remembered: the clock stepped back, and the key is no more forgotten than it was.
func TestMemoryNonceCacheClockStepsBack(t *testing.T) {
	c := verify.NewMemoryNonceCache(15)
	offer(t, c, "a", 100, false)
	offer(t, c, "a", 50, true)
	offer(t, c, "b", 50, false)
	offer(t, c, "a", 115, true)
	offer(t, c, "b", 66, false)
}

// TestMemoryNonceCacheExtremeTimes checks that now - recorded is exact at the ends of int64: a key
// recorded at -2^63 is forgotten by 2^63 - 1, and one recorded at 2^63 - 1 or at 1 is remembered at
// -2^63. Under a TTL of 2^63 - 1, a key recorded at 0 is remembered at 2^63 - 1, and one recorded at -1
// is not.
func TestMemoryNonceCacheExtremeTimes(t *testing.T) {
	c := verify.NewMemoryNonceCache(verify.NonceTTLMs)
	offer(t, c, "a", math.MinInt64, false)
	offer(t, c, "a", math.MaxInt64, false)
	offer(t, c, "a", math.MinInt64, true)
	offer(t, c, "b", 1, false)
	offer(t, c, "b", math.MinInt64, true)
	longest := verify.NewMemoryNonceCache(math.MaxInt64)
	offer(t, longest, "a", 0, false)
	offer(t, longest, "a", math.MaxInt64, true)
	offer(t, longest, "b", -1, false)
	offer(t, longest, "b", math.MaxInt64, false)
}

// TestMemoryNonceCacheZero checks that a zero MemoryNonceCache works, remembering a key for 0 ms.
func TestMemoryNonceCacheZero(t *testing.T) {
	var c verify.MemoryNonceCache
	offer(t, &c, "a", 1, false)
	offer(t, &c, "a", 1, true)
	offer(t, &c, "a", 2, false)
}

// TestMemoryNonceCacheConcurrent offers one key to one cache from 64 goroutines at once: exactly one is
// told the key is new.
func TestMemoryNonceCacheConcurrent(t *testing.T) {
	const n = 64
	for range 50 {
		c := verify.NewMemoryNonceCache(verify.NonceTTLMs)
		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			mu    sync.Mutex
			fresh int
		)
		start.Add(1)
		for range n {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				seen, err := c.SeenBefore(t.Context(), "rid-1|orders|req", 100)
				if err != nil {
					t.Error(err)
				}
				if !seen {
					mu.Lock()
					fresh++
					mu.Unlock()
				}
			}()
		}
		start.Done()
		done.Wait()
		if fresh != 1 {
			t.Fatalf("%d of %d goroutines were told the key is new, want 1", fresh, n)
		}
	}
}
