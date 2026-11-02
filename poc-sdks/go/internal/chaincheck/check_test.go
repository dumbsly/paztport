// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/chaincheck"
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
			if got := chaincheck.Stamps(c, keyring, []string{"gateway"}, "", "payment", tt.rid); got != tt.code {
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
	if got := chaincheck.Route(nil, "payment", true, nil, nil, ""); got != reason.PathNotAllowed {
		t.Fatalf("Route = %s, want PATH_NOT_ALLOWED", got)
	}
}
