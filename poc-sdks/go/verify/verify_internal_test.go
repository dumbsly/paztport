// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"math"
	"strconv"
	"testing"
)

// TestFreshAtExtremeClocks checks check 7's arithmetic directly, since no clock past 2^53 - 1 gets past
// check 0: a clock at either end of int64 is never fresh for stamps at ts 0 under the spec's windows, and
// under windows of 2^63 - 1 is fresh exactly when every difference is within them.
func TestFreshAtExtremeClocks(t *testing.T) {
	tests := []struct {
		now, call, run int64
		want           bool
	}{
		{math.MaxInt64, CallMaxAgeMs, RunMaxAgeMs, false},
		{math.MinInt64, CallMaxAgeMs, RunMaxAgeMs, false},
		{math.MinInt64, CallMaxAgeMs, CallMaxAgeMs, false},
		{math.MaxInt64, math.MaxInt64, math.MaxInt64, true},
		{math.MinInt64 + 1, math.MaxInt64, math.MaxInt64, true},
		{math.MinInt64, math.MaxInt64, math.MaxInt64, false},
	}
	for _, tt := range tests {
		if got := fresh(tt.now, 0, 0, tt.call, tt.run); got != tt.want {
			t.Errorf("fresh(%d, 0, 0, %d, %d) = %t, want %t", tt.now, tt.call, tt.run, got, tt.want)
		}
	}
}

// TestMemoryNonceCachePurges checks that the cache drops the keys it has forgotten, and keeps the rest.
func TestMemoryNonceCachePurges(t *testing.T) {
	c := NewMemoryNonceCache(15)
	for i := range int64(10) {
		if _, err := c.SeenBefore(strconv.FormatInt(i, 10), 100+i); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.SeenBefore("0", 101); err != nil { // a hit adds nothing
		t.Fatal(err)
	}
	if len(c.seen) != 10 || len(c.order) != 10 {
		t.Fatalf("the cache holds %d keys and %d records, want 10 and 10", len(c.seen), len(c.order))
	}
	// At 120, the keys recorded at 100 to 104 are 16 to 20 ms old: forgotten, and dropped.
	if seen, err := c.SeenBefore("5", 120); err != nil || !seen {
		t.Fatalf("SeenBefore(5, 120) = %t, %v, want true", seen, err)
	}
	if len(c.seen) != 5 || len(c.order) != 5 {
		t.Fatalf("the cache holds %d keys and %d records, want 5 and 5", len(c.seen), len(c.order))
	}
	// A key recorded afresh is kept when its earlier record is dropped.
	if seen, err := c.SeenBefore("5", 121); err != nil || seen {
		t.Fatalf("SeenBefore(5, 121) = %t, %v, want false", seen, err)
	}
	if seen, err := c.SeenBefore("9", 124); err != nil || !seen {
		t.Fatalf("SeenBefore(9, 124) = %t, %v, want true", seen, err)
	}
	if _, ok := c.seen["5"]; !ok || len(c.seen) != 2 {
		t.Fatalf("the cache holds %v, want 5 and 9", c.seen)
	}
}
