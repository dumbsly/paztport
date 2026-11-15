// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"reflect"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// servedChain returns the token of the mesh fixture's chain, gateway then orders, signed, each stamp committing
// to the block at its place, and the token of those blocks. A setup is given so a test can break it first.
func servedChain(t *testing.T, s *setup, bs ...stamp.Block) (chain, blocks *string) {
	t.Helper()
	s.attach(t, bs...)
	return ptr(s.token(t)), s.in.Blocks
}

func TestAChainThatReadsWithMatchingBlocksHandsThemOnAsNotVerified(t *testing.T) {
	b := example(t)
	chain, blocks := servedChain(t, mesh(t), stamp.EmptyBlock, b)
	h, serve := verify.ServedUnverified(chain, blocks, settings(t, "example"))
	if !serve || h == nil || h.Verified() {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	got, _ := h.Under("example")
	want := []verify.StampItems{
		{Svc: "gateway"}, {Svc: "orders", Named: true, Items: []string{`{"note":"n1"}`, "7"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Under = %+v; want %+v", got, want)
	}
}

func TestNoBlocksAndEveryExtEmptyHandsOnEntriesThatNameNothing(t *testing.T) {
	chain, _ := servedChain(t, mesh(t), stamp.EmptyBlock, stamp.EmptyBlock)
	h, serve := verify.ServedUnverified(chain, nil, settings(t, "example"))
	if !serve || h == nil {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	got, ok := h.Under("example")
	if !ok || len(got) != 2 || got[0].Named || got[1].Named {
		t.Errorf("Under = %+v, %v", got, ok)
	}
}

func TestNoBlocksWhereAStampCommitsToOneIsNotServed(t *testing.T) {
	chain, _ := servedChain(t, mesh(t), stamp.EmptyBlock, example(t))
	h, serve := verify.ServedUnverified(chain, nil, settings(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestABlockAlteredIsNotServed(t *testing.T) {
	chain, _ := servedChain(t, mesh(t), stamp.EmptyBlock, block(t, map[string][]string{"example": {"1"}}))
	altered := blocksToken(t, stamp.EmptyBlock, block(t, map[string][]string{"example": {"2"}}))
	h, serve := verify.ServedUnverified(chain, altered, settings(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestOneBlockTooFewIsNotServed(t *testing.T) {
	chain, _ := servedChain(t, mesh(t), stamp.EmptyBlock, stamp.EmptyBlock)
	h, serve := verify.ServedUnverified(chain, blocksToken(t, stamp.EmptyBlock), settings(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestBlocksThatAreJSONNullAreNotServed(t *testing.T) {
	chain, _ := servedChain(t, mesh(t), stamp.EmptyBlock, stamp.EmptyBlock)
	null := b64.Encode([]byte("null"))
	for name, c := range map[string]*string{"chain reads": chain, "no chain": nil} {
		h, serve := verify.ServedUnverified(c, &null, settings(t, "example"))
		if serve || h != nil {
			t.Errorf("%s: serve=%v h=%v", name, serve, h)
		}
	}
}

func TestAChainThatDoesNotReadWithBlocksThatReadIsServedWithNothingHandedOn(t *testing.T) {
	h, serve := verify.ServedUnverified(ptr("!not a chain"), blocksToken(t, stamp.EmptyBlock), settings(t, "example"))
	if !serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestAChainThatDoesNotReadWithBlocksThatAreAnObjectIsNotServed(t *testing.T) {
	obj := b64.Encode([]byte("{}"))
	h, serve := verify.ServedUnverified(ptr("!not a chain"), &obj, settings(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestNoChainAndNoBlocksIsServedWithNothingHandedOn(t *testing.T) {
	h, serve := verify.ServedUnverified(nil, nil, settings(t, "example"))
	if !serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

// TestABadSignatureDoesNotMatter breaks the last stamp's signature, so that is the chain's only fault: the
// verifier refuses it at check 3, and a service serving it unverified still hands its items on.
func TestABadSignatureDoesNotMatter(t *testing.T) {
	s := mesh(t)
	s.tamper(1, func(st *stamp.Stamp) { st.Sig = b64.Encode(make([]byte, 64)) })
	chain, blocks := servedChain(t, s, stamp.EmptyBlock, example(t))
	in := s.in
	in.Chain = chain
	r, err := verify.New(s.cfg).Verify(t.Context(), in)
	if err != nil || r.Reason != reason.BadSignature {
		t.Fatalf("the verifier gave %v, %v; the chain's only fault should be BAD_SIGNATURE", r.Reason, err)
	}
	h, serve := verify.ServedUnverified(chain, blocks, settings(t, "example"))
	if !serve || h == nil {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	if got, _ := h.Under("example"); len(got) != 2 || !got[1].Named {
		t.Errorf("Under = %+v, want two stamps, the second named", got)
	}
}

func TestANameOutsideTheAllowedListIsNeverHandedOn(t *testing.T) {
	b := block(t, map[string][]string{"example": {"1"}, "other": {"2"}})
	chain, blocks := servedChain(t, mesh(t), stamp.EmptyBlock, b)
	h, serve := verify.ServedUnverified(chain, blocks, allowing(t, []string{"example"}, []string{"example"}))
	if !serve || h == nil {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	if got := h.Names(); !reflect.DeepEqual(got, []string{"example"}) {
		t.Errorf("Names = %v", got)
	}
	if _, ok := h.Under("other"); ok {
		t.Error("Under(other) is held")
	}
}

func TestALastBlockRequiringAnExtensionNotActedOnIsStillServed(t *testing.T) {
	chain, blocks := servedChain(t, mesh(t), stamp.EmptyBlock, block(t, nil, "influence"))
	h, serve := verify.ServedUnverified(chain, blocks, settings(t, "example"))
	if !serve || h == nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}
