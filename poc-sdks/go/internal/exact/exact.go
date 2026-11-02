// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package exact

// AtMost reports whether a - b <= limit, computed exactly: a difference too large for an int64 is above
// every limit, and one too small for it is below every limit.
func AtMost(a, b, limit int64) bool {
	d := a - b
	if (b > 0 && d > a) || (b < 0 && d < a) {
		// The difference overflowed, so its sign is the side of b that a is on.
		return a < b
	}
	return d <= limit
}
