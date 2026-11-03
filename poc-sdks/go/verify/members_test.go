// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"bytes"
	"math"
	"strconv"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// route is the fixture's route, which every tree below holds.
const route = "gateway/orders/payment"

// tree returns the root, with no window, of a one-level tree of the fixture's route labelled rootID, its
// salt and its sibling filled with fill so that each fill gives its own root. proofIn gives the route's
// proof in it.
func tree(t *testing.T, rootID string, fill byte) verify.PinnedRoot {
	t.Helper()
	salt, sibling := bytes.Repeat([]byte{fill}, 16), bytes.Repeat([]byte{fill}, 32)
	leaf, err := policy.LeafHash(salt, route)
	if err != nil {
		t.Fatal(err)
	}
	return verify.PinnedRoot{Root: policy.NodeHash(leaf, sibling), RootID: rootID, NotAfter: math.MaxInt64}
}

// proofIn returns the route's proof in the tree of fill, labelled rootID: the tree's own rootId, or another
// to relabel it.
func proofIn(t *testing.T, fill byte, rootID string) *string {
	t.Helper()
	p := policy.Proof{
		LeafSalt: bytes.Repeat([]byte{fill}, 16),
		Siblings: [][]byte{bytes.Repeat([]byte{fill}, 32)},
		Dirs:     "L",
		RootID:   rootID,
	}
	tok, err := p.Token()
	if err != nil {
		t.Fatal(err)
	}
	return &tok
}

// until returns r with the window notAfter.
func until(r verify.PinnedRoot, notAfter int64) verify.PinnedRoot {
	r.NotAfter = notAfter
	return r
}

// ring returns a keyring until notAfter that gives each service of keys the vector key of the name it
// maps to.
func ring(t *testing.T, notAfter int64, keys map[string]string) verify.PinnedKeyring {
	t.Helper()
	k := policy.Keyring{}
	for svc, name := range keys {
		k[svc] = pub(t, name)
	}
	return verify.PinnedKeyring{Keys: k, NotAfter: notAfter}
}

// The services' keys the keyrings below hold, each the vector key called by the name it maps to: gateway's,
// orders', both, and both with orders' old key, which is pi's.
var (
	gatewayKey = map[string]string{"gateway": "gateway"}
	ordersKey  = map[string]string{"orders": "orders"}
	bothKeys   = map[string]string{"gateway": "gateway", "orders": "orders"}
	oldKeys    = map[string]string{"gateway": "gateway", "orders": "pi"}
)

// TestVerifyKeyrings checks check 4 against several keyrings: a stamp's key is looked up by its own
// service's name in every current keyring, and its signature must verify under one of the keys they give
// it.
func TestVerifyKeyrings(t *testing.T) {
	const far = 4102444800000
	tests := []struct {
		name     string
		keyrings func(t *testing.T) []verify.PinnedKeyring
		code     reason.Code
	}{
		{"one keyring", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, bothKeys)}
		}, reason.OK},
		{"a key only in the second keyring, the first giving an old one", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, oldKeys), ring(t, far, ordersKey)}
		}, reason.OK},
		{"a key only in the second keyring, the first giving none", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, gatewayKey), ring(t, far, bothKeys)}
		}, reason.OK},
		{"the new key first, the old second", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, bothKeys), ring(t, far, oldKeys)}
		}, reason.OK},
		{"the chain's keys from two keyrings", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, gatewayKey), ring(t, far, ordersKey)}
		}, reason.OK},
		{"the chain's keys from two keyrings, the other way round", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, ordersKey), ring(t, far, gatewayKey)}
		}, reason.OK},
		{"a key only in an expired keyring, beside an old one", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, oldKeys), ring(t, now-1, ordersKey)}
		}, reason.BadSignature},
		{"a key only in an expired keyring", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, gatewayKey), ring(t, now-1, ordersKey)}
		}, reason.BadSignature},
		{"only old keys", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, oldKeys), ring(t, far, oldKeys)}
		}, reason.BadSignature},
		{"orders' key under another name", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, map[string]string{"gateway": "gateway", "other": "orders"})}
		}, reason.BadSignature},
		{"orders' key under other names in a second keyring", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{ring(t, far, oldKeys),
				ring(t, far, map[string]string{"Orders": "orders", "orders-1": "orders", "gateway": "orders"})}
		}, reason.BadSignature},
		{"a keyring of no keys", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{{NotAfter: far}, ring(t, far, bothKeys)}
		}, reason.OK},
		{"no keyring", func(t *testing.T) []verify.PinnedKeyring { return nil }, reason.BadSignature},
		{"only keyrings of no keys", func(t *testing.T) []verify.PinnedKeyring {
			return []verify.PinnedKeyring{{NotAfter: far}, {Keys: policy.Keyring{}, NotAfter: far}}
		}, reason.BadSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.cfg.Keyrings = tt.keyrings(t)
			if got, want := s.run(t), s.named(tt.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestVerifyRoots checks check 11 against several roots: the proof's rootId selects the current roots
// with that rootId, and the route must prove against one of them.
func TestVerifyRoots(t *testing.T) {
	// first and second are two trees under their own rootIds; renewed renews first under its rootId, and
	// unpinned is pinned nowhere.
	const first, second, renewed, unpinned = 1, 2, 3, 4
	tests := []struct {
		name  string
		roots func(t *testing.T) []verify.PinnedRoot
		proof func(t *testing.T) *string
		code  reason.Code
	}{
		{"a proof under the first root", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, first, "v1") }, reason.OK},
		{"a proof under the second root", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, second, "v2") }, reason.OK},
		{"a proof whose rootId is pinned nowhere", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, unpinned, "v4") }, reason.PathNotAllowed},
		{"the second tree's proof relabelled with the first's rootId", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, second, "v1") }, reason.PathNotAllowed},
		{"the first tree's proof relabelled with the second's rootId", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, first, "v2") }, reason.PathNotAllowed},
		{"the same, the roots the other way round", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v2", second), tree(t, "v1", first)}
		}, func(t *testing.T) *string { return proofIn(t, first, "v2") }, reason.PathNotAllowed},
		{"a proof under an expired root, another current", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{until(tree(t, "v1", first), now-1), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, first, "v1") }, reason.PathNotAllowed},
		{"a proof under the current root, another expired", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{until(tree(t, "v1", first), now-1), tree(t, "v2", second)}
		}, func(t *testing.T) *string { return proofIn(t, second, "v2") }, reason.OK},
		{"a proof under a root, its renewal pinned too", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v1", renewed)}
		}, func(t *testing.T) *string { return proofIn(t, first, "v1") }, reason.OK},
		{"a proof under the renewal, the old root pinned too", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first), tree(t, "v1", renewed)}
		}, func(t *testing.T) *string { return proofIn(t, renewed, "v1") }, reason.OK},
		{"a proof under the renewal, only the old root pinned", func(t *testing.T) []verify.PinnedRoot {
			return []verify.PinnedRoot{tree(t, "v1", first)}
		}, func(t *testing.T) *string { return proofIn(t, renewed, "v1") }, reason.PathNotAllowed},
		{"no root", func(t *testing.T) []verify.PinnedRoot { return nil },
			func(t *testing.T) *string { return proofIn(t, first, "v1") }, reason.PathNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.cfg.Roots = tt.roots(t)
			s.in.Proof = tt.proof(t)
			if got, want := s.run(t), s.named(tt.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestVerifyMemberWindows checks when a keyring or a root is current: while the clock is at most its
// notAfter, a protocol integer, or always for math.MaxInt64, which is no window. Any other window is
// current at no time. Check 0 is the Config's PolicyNotAfter alone, so each member is judged by checks 4
// and 11.
func TestVerifyMemberWindows(t *testing.T) {
	tests := []struct {
		window int64
		ok     bool
	}{
		{now, true},
		{now - 1, false},
		{now + 1, true},
		{json.MaxSafe, true},
		{math.MaxInt64, true},
		{json.MaxSafe + 1, false},
		{math.MaxInt64 - 1, false},
		{-1, false},
		{math.MinInt64, false},
	}
	for _, tt := range tests {
		t.Run("a keyring until "+strconv.FormatInt(tt.window, 10), func(t *testing.T) {
			s := mesh(t)
			s.cfg.Keyrings = []verify.PinnedKeyring{ring(t, 4102444800000, gatewayKey), ring(t, tt.window, ordersKey)}
			want := s.named(reason.BadSignature)
			if tt.ok {
				want = s.named(reason.OK)
			}
			if got := s.run(t); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
		t.Run("a root until "+strconv.FormatInt(tt.window, 10), func(t *testing.T) {
			s := mesh(t)
			s.cfg.Roots[0].NotAfter = tt.window
			want := s.named(reason.PathNotAllowed)
			if tt.ok {
				want = s.named(reason.OK)
			}
			if got := s.run(t); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}
