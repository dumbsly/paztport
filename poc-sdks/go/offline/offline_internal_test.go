// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline

import (
	"math"
	"testing"
)

// TestWithinAgeAtExtremeTimes holds the age arithmetic to times and limits at the ends of int64, which no
// chain that reads can carry: each difference is compared exactly, so one too large for an int64 is above
// every limit and one too small is below every limit, and none wraps to the other side.
func TestWithinAgeAtExtremeTimes(t *testing.T) {
	limit := func(n int64) *int64 { return &n }
	tests := []struct {
		name         string
		origin, last int64
		run, call    int64
		want         bool
	}{
		{"a run of 2^64 - 1", math.MinInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64, false},
		{"an origin 2^64 - 1 after the last", math.MaxInt64, math.MinInt64, math.MaxInt64, math.MaxInt64, false},
		{"a run of 2^63 - 1", 0, math.MaxInt64, math.MaxInt64, math.MaxInt64, true},
		{"a run of 2^63", -1, math.MaxInt64, math.MaxInt64, math.MaxInt64, false},
		{"an origin 2^63 after the last", math.MaxInt64, -1, math.MaxInt64, math.MaxInt64, false},
		{"an origin 2^63 - 1 after the last", math.MaxInt64, 0, math.MinInt64, math.MaxInt64, false},
		{"limits of -2^63, at once", 0, 0, math.MinInt64, math.MinInt64, false},
		{"limits of 0, at once", math.MinInt64, math.MinInt64, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withinAge(tt.origin, tt.last, limit(tt.run), limit(tt.call)); got != tt.want {
				t.Fatalf("withinAge = %t, want %t", got, tt.want)
			}
		})
	}
}
