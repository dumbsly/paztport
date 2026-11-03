// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"crypto/ed25519"
	"math"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/chaincheck"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// chain signs a chain from gateway to orders, for payment, with rid as every stamp's rid.
func chain(t *testing.T, rid string) (stamp.Chain, policy.Keyring) {
	t.Helper()
	keyring := policy.Keyring{}
	c := stamp.Chain{
		{Svc: "gateway", Inst: "gw-1", RID: rid, TS: 1, Rcv: "orders", Bind: "bind-0"},
		{Svc: "orders", Inst: "ord-1", RID: rid, TS: 2, Rcv: "payment", Bind: "bind-1"},
	}
	for i, s := range c {
		if i > 0 {
			s.Prev = c[i-1].Sig
		}
		priv, pub := vectors.V3Key(t, s.Svc)
		keyring[s.Svc] = pub
		signed, err := stamp.Sign(s, priv)
		if err != nil {
			t.Fatal(err)
		}
		c[i] = signed
	}
	return c, keyring
}

// TestStampsRID checks check 5's rid: the origin's when none is given, and otherwise the one given, ""
// included, which is a rid like any other and not a request for the origin's.
func TestStampsRID(t *testing.T) {
	ptr := func(s string) *string { return &s }
	tests := []struct {
		name  string
		chain string
		rid   *string
		code  reason.Code
	}{
		{"the origin's", "rid-1", nil, reason.OK},
		{"the one given", "rid-1", ptr("rid-1"), reason.OK},
		{"another one given", "rid-1", ptr("rid-2"), reason.RIDMismatch},
		{"an empty one given", "rid-1", ptr(""), reason.RIDMismatch},
		{"an empty one, given and carried", "", ptr(""), reason.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, keyring := chain(t, tt.chain)
			got := chaincheck.Stamps(c, []policy.Keyring{keyring}, []string{"gateway"}, "", "payment", tt.rid)
			if got != tt.code {
				t.Fatalf("Stamps = %s, want %s", got, tt.code)
			}
		})
	}
}

// TestStampsEmptyChain checks that an empty chain, which no reader returns, is CHAIN_MISSING and not a
// panic.
func TestStampsEmptyChain(t *testing.T) {
	if got := chaincheck.Stamps(nil, nil, nil, "", "payment", nil); got != reason.ChainMissing {
		t.Fatalf("Stamps = %s, want CHAIN_MISSING", got)
	}
	if got := chaincheck.Route(nil, "payment", true, nil, nil); got != reason.PathNotAllowed {
		t.Fatalf("Route = %s, want PATH_NOT_ALLOWED", got)
	}
}

// TestCurrent pins when a member is current: its window is math.MaxInt64, for none, or a protocol integer,
// and the time is at most it. Any other window is current at no time.
func TestCurrent(t *testing.T) {
	tests := []struct {
		notAfter, at int64
		want         bool
	}{
		{100, 100, true},
		{100, 99, true},
		{100, 101, false},
		{0, 0, true},
		{0, math.MinInt64, true},
		{json.MaxSafe, json.MaxSafe, true},
		{json.MaxSafe, json.MaxSafe + 1, false},
		{math.MaxInt64, math.MaxInt64, true},
		{math.MaxInt64, math.MinInt64, true},
		{json.MaxSafe + 1, 0, false},
		{math.MaxInt64 - 1, 0, false},
		{-1, -2, false},
		{-1, math.MinInt64, false},
		{math.MinInt64, math.MinInt64, false},
	}
	for _, tt := range tests {
		if got := chaincheck.Current(tt.notAfter, tt.at); got != tt.want {
			t.Errorf("Current(%d, %d) = %t, want %t", tt.notAfter, tt.at, got, tt.want)
		}
	}
}

// TestKeysFor checks that the keys keyrings give a service are looked up by its own name in each, in their
// order, each distinct key once however many keyrings hold it, and that none is none.
func TestKeysFor(t *testing.T) {
	_, a := vectors.V3Key(t, "gateway")
	_, b := vectors.V3Key(t, "orders")
	copyOfA := ed25519.PublicKey(slices.Clone(a))
	keyrings := []policy.Keyring{
		{"orders": a},
		nil,
		{"orders": copyOfA, "Orders": b},
		{"orders": b, "gateway": a},
		{"orders-1": b},
	}
	got := chaincheck.KeysFor(keyrings, "orders")
	if len(got) != 2 || !got[0].Equal(a) || !got[1].Equal(b) {
		t.Fatalf("KeysFor = %x, want %x then %x", got, a, b)
	}
	for _, svc := range []string{"payment", "", "Orders "} {
		if got := chaincheck.KeysFor(keyrings[:2], svc); len(got) != 0 {
			t.Errorf("KeysFor(%q) = %x, want none", svc, got)
		}
	}
	if got := chaincheck.KeysFor(nil, "orders"); len(got) != 0 {
		t.Errorf("KeysFor of no keyring = %x, want none", got)
	}
}
