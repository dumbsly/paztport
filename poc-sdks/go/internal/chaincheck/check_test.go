// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"math"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
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
		priv, pub := vectors.VectorKey(t, s.Svc)
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
	if got := chaincheck.Route(nil, true, nil, nil); got != reason.PathNotAllowed {
		t.Fatalf("Route = %s, want PATH_NOT_ALLOWED", got)
	}
	tok := "W10" // the token of []
	for _, in := range []*string{nil, &tok} {
		if bs, got := chaincheck.Match(nil, in); got != reason.OK || len(bs) != 0 {
			t.Fatalf("Match = %v, %s, want no blocks and OK", bs, got)
		}
		if bs, got := chaincheck.Blocks(nil, in, carryAll, actsOn("example"), true); got != reason.OK || len(bs) != 0 {
			t.Fatalf("Blocks = %v, %s, want no blocks and OK", bs, got)
		}
	}
}

// TestBinding pins check 8: the last stamp's bind is the one expected, "" included, and none expected matches
// nothing.
func TestBinding(t *testing.T) {
	ptr := func(s string) *string { return &s }
	for _, tt := range []struct {
		bind     string
		expected *string
		code     reason.Code
	}{
		{"bind-1", ptr("bind-1"), reason.OK},
		{"", ptr(""), reason.OK},
		{"bind-1", ptr("bind-2"), reason.BindingMismatch},
		{"", nil, reason.BindingMismatch},
		{"bind-1", nil, reason.BindingMismatch},
	} {
		if got := chaincheck.Binding(stamp.Stamp{Bind: tt.bind}, tt.expected); got != tt.code {
			t.Errorf("Binding(%q, %v) = %s, want %s", tt.bind, tt.expected, got, tt.code)
		}
	}
}

// block returns the block naming each extension in items with its items, requiring requires.
func block(t *testing.T, items map[string][]string, requires ...string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(items, requires)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// token returns the token of bs.
func token(t *testing.T, bs ...stamp.Block) *string {
	t.Helper()
	tok, err := stamp.Blocks(bs).Token()
	if err != nil {
		t.Fatal(err)
	}
	return &tok
}

// committed returns a two-stamp chain whose stamps commit to bs, one ext per stamp. Check 9a reads ext as text,
// so the stamps need no signature.
func committed(bs ...stamp.Block) stamp.Chain {
	c := stamp.Chain{{Svc: "gateway", Rcv: "orders"}, {Svc: "orders", Rcv: "payment"}}
	for i, b := range bs {
		c[i].Ext = b.Commit()
	}
	return c
}

// carryAll carries every name, as settings with no list do.
func carryAll(string) bool { return true }

// actsOn returns the predicate of settings acting on names.
func actsOn(names ...string) func(string) bool {
	return func(n string) bool { return slices.Contains(names, n) }
}

// TestMatch pins check 9a alone: one block per stamp, each committing to its stamp's ext, compared as text; an
// absent token is one empty block per stamp, while a token that reads as anything but an array of blocks, null
// and "" among them, is EXTENSION_MISMATCH. The blocks come back on OK only.
func TestMatch(t *testing.T) {
	ex := block(t, map[string][]string{"example": {`{"note":"n1"}`, "7"}}, "example")
	empty := stamp.EmptyBlock
	null, blank, object := "bnVsbA", "", "e30" // the tokens of null, of no bytes, and of {}
	notB64 := committed(empty, ex)
	notB64[1].Ext = "not base64url!"
	hashOfEmpty := committed(empty, empty)
	hashOfEmpty[1].Ext = "VoOAqZrz-hqbulk2GETeNxx5p43bDqFNbKY-EGzv1cM" // b64url(SHA-256({"items":{},"requires":[]}))
	for _, tt := range []struct {
		name  string
		chain stamp.Chain
		tok   *string
		code  reason.Code
	}{
		{"no token, every ext empty", committed(empty, empty), nil, reason.OK},
		{"an array of empty blocks", committed(empty, empty), token(t, empty, empty), reason.OK},
		{"blocks matching", committed(empty, ex), token(t, empty, ex), reason.OK},
		{"no token where a stamp commits to a block", committed(empty, ex), nil, reason.ExtensionMismatch},
		{"a token of null", committed(empty, empty), &null, reason.ExtensionMismatch},
		{"an empty token", committed(empty, empty), &blank, reason.ExtensionMismatch},
		{"a token of an object", committed(empty, empty), &object, reason.ExtensionMismatch},
		{"one block too few", committed(empty, empty), token(t, empty), reason.ExtensionMismatch},
		{"one block too many", committed(empty, empty), token(t, empty, empty, empty), reason.ExtensionMismatch},
		{"two blocks swapped", committed(ex, empty), token(t, empty, ex), reason.ExtensionMismatch},
		{"an item altered", committed(empty, ex),
			token(t, empty, block(t, map[string][]string{"example": {`{"note":"n2"}`, "7"}}, "example")),
			reason.ExtensionMismatch},
		{"an ext that is not base64url", notB64, token(t, empty, ex), reason.ExtensionMismatch},
		{"an ext that is the hash of the empty block", hashOfEmpty, token(t, empty, empty), reason.ExtensionMismatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bs, got := chaincheck.Match(tt.chain, tt.tok)
			if got != tt.code {
				t.Fatalf("Match = %s, want %s", got, tt.code)
			}
			if got != reason.OK {
				if bs != nil {
					t.Fatalf("Match refused with blocks %v", bs)
				}
				return
			}
			if len(bs) != len(tt.chain) {
				t.Fatalf("Match gave %d blocks for %d stamps", len(bs), len(tt.chain))
			}
			for i, b := range bs {
				if b.Commit() != tt.chain[i].Ext {
					t.Errorf("block %d commits to %q, its stamp to %q", i, b.Commit(), tt.chain[i].Ext)
				}
			}
		})
	}
	if sum := sha256.Sum256(stamp.EmptyBlock.Wire()); hashOfEmpty[1].Ext != b64.Encode(sum[:]) {
		t.Fatal("the test's hash of the empty block is not its hash")
	}
}

// TestBlocks pins checks 9b and 9c after 9a: a name in any block's items or requires outside the carried names is
// EXTENSION_NOT_ALLOWED, and live, a name the last block requires that the service does not act on is
// EXTENSION_REQUIRED; an earlier block's requires binds no one, and offline 9c does not run. 9a comes first.
func TestBlocks(t *testing.T) {
	empty := stamp.EmptyBlock
	names := block(t, map[string][]string{"other": {}})
	requiresOther := block(t, nil, "other")
	requiresTwo := block(t, nil, "example", "other")
	carryExample := actsOn("example")
	for _, tt := range []struct {
		name    string
		blocks  []stamp.Block
		carries func(string) bool
		actsOn  func(string) bool
		live    bool
		code    reason.Code
	}{
		{"a name in items not carried", []stamp.Block{empty, names}, carryExample, carryExample, true,
			reason.ExtensionNotAllowed},
		{"a name only in the first block's requires not carried", []stamp.Block{requiresOther, empty}, carryExample,
			carryAll, true, reason.ExtensionNotAllowed},
		{"the same, offline", []stamp.Block{requiresOther, empty}, carryExample, carryAll, false,
			reason.ExtensionNotAllowed},
		{"a name in items, every name carried", []stamp.Block{empty, names}, carryAll, actsOn(), true, reason.OK},
		{"the last block requires what is not acted on", []stamp.Block{empty, requiresOther}, carryAll,
			carryExample, true, reason.ExtensionRequired},
		{"the same, offline", []stamp.Block{empty, requiresOther}, carryAll, carryExample, false, reason.OK},
		{"an earlier block requires what is not acted on", []stamp.Block{requiresOther, empty}, carryAll,
			carryExample, true, reason.OK},
		{"two required, one acted on", []stamp.Block{empty, requiresTwo}, carryAll, carryExample, true,
			reason.ExtensionRequired},
		{"two required, both acted on", []stamp.Block{empty, requiresTwo}, carryAll, actsOn("example", "other"), true,
			reason.OK},
		{"not carried and not acted on: 9b first", []stamp.Block{empty, requiresOther}, carryExample, carryExample,
			true, reason.ExtensionNotAllowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := committed(tt.blocks...)
			bs, got := chaincheck.Blocks(c, token(t, tt.blocks...), tt.carries, tt.actsOn, tt.live)
			if got != tt.code {
				t.Fatalf("Blocks = %s, want %s", got, tt.code)
			}
			if (bs != nil) != (got == reason.OK) {
				t.Fatalf("Blocks gave %v with %s", bs, got)
			}
		})
	}
	// 9a before 9b and 9c: a block that is not its stamp's is refused before any name in it is read.
	c := committed(empty, empty)
	if _, got := chaincheck.Blocks(c, token(t, empty, requiresOther), carryExample, carryExample, true); got !=
		reason.ExtensionMismatch {
		t.Fatalf("Blocks = %s, want EXTENSION_MISMATCH", got)
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
	_, a := vectors.VectorKey(t, "gateway")
	_, b := vectors.VectorKey(t, "orders")
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
