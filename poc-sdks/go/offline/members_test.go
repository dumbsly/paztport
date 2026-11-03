// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// keyringOf returns a keyring of the named services' own vector keys, until notAfter.
func keyringOf(t *testing.T, notAfter int64, svcs ...string) verify.PinnedKeyring {
	t.Helper()
	k := policy.Keyring{}
	for _, svc := range svcs {
		k[svc] = pub(t, svc)
	}
	return verify.PinnedKeyring{Keys: k, NotAfter: notAfter}
}

// TestOfflineMemberWindows checks that a keyring or a root counts for a record when the record's recorded
// time, its last stamp's, is at most its notAfter, and always for math.MaxInt64, which is no window: a
// record that none of the keyrings, or none of the roots, counts for is POLICY_EXPIRED, and checks 4 and 11
// use only those that count.
func TestOfflineMemberWindows(t *testing.T) {
	tests := []struct {
		name string
		make func(t *testing.T, s *setup)
		code reason.Code
	}{
		{"a keyring until the record's time", func(t *testing.T, s *setup) {
			s.cfg.Keyrings[0].NotAfter = end
		}, reason.OK},
		{"a keyring until 1 ms before it", func(t *testing.T, s *setup) {
			s.cfg.Keyrings[0].NotAfter = end - 1
		}, reason.PolicyExpired},
		{"a root until the record's time", func(t *testing.T, s *setup) {
			s.cfg.Roots[0].NotAfter = end
		}, reason.OK},
		{"a root until 1 ms before it", func(t *testing.T, s *setup) {
			s.cfg.Roots[0].NotAfter = end - 1
		}, reason.PolicyExpired},
		{"a keyring that lapsed before the record, another that counts", func(t *testing.T, s *setup) {
			s.cfg.Keyrings = []verify.PinnedKeyring{keyringOf(t, end-1, "gateway", "orders"),
				keyringOf(t, end, "gateway", "orders")}
		}, reason.OK},
		{"the origin's key in a keyring that counts, the last's in one that lapsed", func(t *testing.T, s *setup) {
			s.cfg.Keyrings = []verify.PinnedKeyring{keyringOf(t, math.MaxInt64, "gateway"),
				keyringOf(t, end-1, "orders")}
		}, reason.BadSignature},
		{"the chain's keys from two keyrings that count", func(t *testing.T, s *setup) {
			s.cfg.Keyrings = []verify.PinnedKeyring{keyringOf(t, math.MaxInt64, "orders"),
				keyringOf(t, end, "gateway")}
		}, reason.OK},
		{"the proof's root lapsed before the record, another counts", func(t *testing.T, s *setup) {
			other := s.cfg.Roots[0]
			other.Root, other.RootID = []byte("another tree"), "v9"
			s.cfg.Roots[0].NotAfter = end - 1
			s.cfg.Roots = append(s.cfg.Roots, other)
		}, reason.PathNotAllowed},
		{"the proof's root renewed: the old lapsed, the renewal counts", func(t *testing.T, s *setup) {
			old := s.cfg.Roots[0]
			old.Root, old.NotAfter = []byte("the old tree"), end-1
			s.cfg.Roots = append([]verify.PinnedRoot{old}, s.cfg.Roots...)
		}, reason.OK},
		{"no keyring", func(t *testing.T, s *setup) { s.cfg.Keyrings = nil }, reason.PolicyExpired},
		{"no root", func(t *testing.T, s *setup) { s.cfg.Roots = []verify.PinnedRoot{} }, reason.PolicyExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			tt.make(t, s)
			if got, want := s.run(t), named(tt.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
	for _, window := range []int64{json.MaxSafe, math.MaxInt64} {
		t.Run("a window of "+strconv.FormatInt(window, 10), func(t *testing.T) {
			s := mesh(t)
			s.cfg.Keyrings[0].NotAfter, s.cfg.Roots[0].NotAfter = window, window
			if got, want := s.run(t), named(reason.OK); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
	for _, window := range []int64{json.MaxSafe + 1, math.MaxInt64 - 1, -1, math.MinInt64} {
		t.Run("a window of "+strconv.FormatInt(window, 10)+", which counts for no record", func(t *testing.T) {
			for _, member := range []string{"keyring", "root"} {
				s := mesh(t)
				if member == "keyring" {
					s.cfg.Keyrings[0].NotAfter = window
				} else {
					s.cfg.Roots[0].NotAfter = window
				}
				if got, want := s.run(t), named(reason.PolicyExpired); got != want {
					t.Fatalf("a %s's: Verify = %+v, want %+v", member, got, want)
				}
			}
		})
	}
}

// TestOfflinePolicyExpiredFirst checks that offline check 0 comes before check 1, names no one and spends no
// key: the record set can still spend the chain's key once its material counts.
func TestOfflinePolicyExpiredFirst(t *testing.T) {
	s := mesh(t)
	s.cfg.Roots[0].NotAfter = end - 1
	if got, want := s.run(t), named(reason.PolicyExpired); got != want {
		t.Fatalf("Verify = %+v, want %+v", got, want)
	}
	s.cfg.Roots[0].NotAfter = end
	if got, want := s.run(t), named(reason.OK); got != want {
		t.Fatalf("Verify = %+v once the root counts, want %+v: POLICY_EXPIRED spent the key", got, want)
	}
	none := mesh(t)
	none.cfg.Keyrings = nil
	none.stamps = nil
	if got, want := none.run(t), named(reason.PolicyExpired); got != want {
		t.Fatalf("Verify = %+v with no chain, want %+v", got, want)
	}
}

// TestOfflineRecordWithNoTime checks that a record with no recorded time is left to check 7: every member
// with a well-formed window counts for it, however early, so it is TIME_MISMATCH, and only a record with
// no member that could ever count is POLICY_EXPIRED.
func TestOfflineRecordWithNoTime(t *testing.T) {
	tests := []struct {
		name   string
		window int64
		code   reason.Code
	}{
		{"members with no window", math.MaxInt64, reason.TimeMismatch},
		{"members until a time before the stamps'", start - 1, reason.TimeMismatch},
		{"members until 0", 0, reason.TimeMismatch},
		{"members with a window out of range", -1, reason.PolicyExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.in.Recorded = nil
			s.cfg.Keyrings[0].NotAfter, s.cfg.Roots[0].NotAfter = tt.window, tt.window
			if got, want := s.run(t), named(tt.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestOfflineConfigIsNotChanged checks that verifying a record leaves the Config's keyrings and roots as
// they were, those that do not count for it included.
func TestOfflineConfigIsNotChanged(t *testing.T) {
	s := mesh(t)
	s.cfg.Keyrings = append([]verify.PinnedKeyring{keyringOf(t, end-1, "orders")}, s.cfg.Keyrings...)
	s.cfg.Roots = append([]verify.PinnedRoot{{Root: []byte("the old tree"), NotAfter: end - 1}}, s.cfg.Roots...)
	if got, want := s.run(t), named(reason.OK); got != want {
		t.Fatalf("Verify = %+v, want %+v", got, want)
	}
	if len(s.cfg.Keyrings) != 2 || s.cfg.Keyrings[0].NotAfter != end-1 || s.cfg.Keyrings[1].NotAfter != math.MaxInt64 ||
		len(s.cfg.Roots) != 2 || s.cfg.Roots[0].NotAfter != end-1 || s.cfg.Roots[1].NotAfter != math.MaxInt64 {
		t.Fatalf("the Config is now %+v", s.cfg)
	}
}
