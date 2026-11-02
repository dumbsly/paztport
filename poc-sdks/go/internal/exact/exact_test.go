// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package exact_test

import (
	"math"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
)

// TestAtMost pins the exact difference at both ends of int64: one that overflows above is above every
// limit, one that overflows below is below every limit, and one that fits is compared as it is.
func TestAtMost(t *testing.T) {
	tests := []struct {
		name        string
		a, b, limit int64
		want        bool
	}{
		{"2^63, the least overflow above", math.MaxInt64, -1, math.MaxInt64, false},
		{"2^64 - 1, the most above", math.MaxInt64, math.MinInt64, math.MaxInt64, false},
		{"-2^63 - 1, the least overflow below", math.MinInt64, 1, math.MinInt64, true},
		{"-2^64 + 1, the most below", math.MinInt64, math.MaxInt64, math.MinInt64, true},
		{"2^63 - 1, at the limit", math.MaxInt64, 0, math.MaxInt64, true},
		{"2^63 - 1, one past the limit", 0, math.MinInt64 + 1, math.MaxInt64 - 1, false},
		{"-2^63, at the limit", math.MinInt64, 0, math.MinInt64, true},
		{"-2^63 + 1, one past the limit", math.MinInt64 + 1, 0, math.MinInt64, false},
		{"0 against a limit of -2^63", math.MinInt64, math.MinInt64, math.MinInt64, false},
		{"0 against a limit of 0", math.MaxInt64, math.MaxInt64, 0, true},
		{"a small difference at the limit", 7, 2, 5, true},
		{"a small difference past the limit", 7, 2, 4, false},
	}
	for _, tt := range tests {
		if got := exact.AtMost(tt.a, tt.b, tt.limit); got != tt.want {
			t.Errorf("%s: AtMost(%d, %d, %d) = %t, want %t", tt.name, tt.a, tt.b, tt.limit, got, tt.want)
		}
	}
}
