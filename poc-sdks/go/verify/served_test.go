// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"reflect"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// servedChain returns the token of a chain of gateway then orders, each stamp committing to the block at its
// place; no stamp is signed, since ServedUnverified needs no key.
func servedChain(t *testing.T, bs stamp.Blocks) *string {
	t.Helper()
	c := stamp.Chain{
		{Svc: "gateway", RID: "r", Rcv: "orders", Ext: bs[0].Commit()},
		{Svc: "orders", RID: "r", Rcv: "inventory", Ext: bs[1].Commit(), Prev: ""},
	}
	tok, err := c.Token()
	if err != nil {
		t.Fatal(err)
	}
	return &tok
}

func servedBlocks(t *testing.T, bs stamp.Blocks) *string {
	t.Helper()
	tok, err := bs.Token()
	if err != nil {
		t.Fatal(err)
	}
	return &tok
}

func exampleBlock(t *testing.T, item string, name string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{name: {item}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func actingOn(t *testing.T, actsOn ...string) verify.Extensions {
	t.Helper()
	ext, err := verify.NewExtensions(actsOn)
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

func strp(s string) *string { return &s }

func TestAChainThatReadsWithMatchingBlocksHandsThemOnAsNotVerified(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, exampleBlock(t, `{"n":1}`, "example")}
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, bs), actingOn(t, "example"))
	if !serve || h == nil || h.Verified() {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	got, _ := h.Under("example")
	want := []verify.StampItems{{Svc: "gateway"}, {Svc: "orders", Named: true, Items: []string{`{"n":1}`}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Under = %+v; want %+v", got, want)
	}
}

func TestNoBlocksAndEveryExtEmptyHandsOnEntriesThatNameNothing(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, stamp.EmptyBlock}
	h, serve := verify.ServedUnverified(servedChain(t, bs), nil, actingOn(t, "example"))
	if !serve || h == nil {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	got, ok := h.Under("example")
	if !ok || len(got) != 2 || got[0].Named || got[1].Named {
		t.Errorf("Under = %+v, %v", got, ok)
	}
}

func TestNoBlocksWhereAStampCommitsToOneIsNotServed(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, exampleBlock(t, "1", "example")}
	h, serve := verify.ServedUnverified(servedChain(t, bs), nil, actingOn(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestABlockAlteredIsNotServed(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, exampleBlock(t, "1", "example")}
	other := stamp.Blocks{stamp.EmptyBlock, exampleBlock(t, "2", "example")}
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, other), actingOn(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestOneBlockTooFewIsNotServed(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, stamp.EmptyBlock}
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, bs[:1]), actingOn(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestBlocksThatAreJSONNullAreNotServed(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, stamp.EmptyBlock}
	null := b64.Encode([]byte("null"))
	for name, chain := range map[string]*string{"chain reads": servedChain(t, bs), "no chain": nil} {
		h, serve := verify.ServedUnverified(chain, &null, actingOn(t, "example"))
		if serve || h != nil {
			t.Errorf("%s: serve=%v h=%v", name, serve, h)
		}
	}
}

func TestAChainThatDoesNotReadWithBlocksThatReadIsServedWithNothingHandedOn(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock}
	h, serve := verify.ServedUnverified(strp("!not a chain"), servedBlocks(t, bs), actingOn(t, "example"))
	if !serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestAChainThatDoesNotReadWithBlocksThatAreAnObjectIsNotServed(t *testing.T) {
	obj := b64.Encode([]byte("{}"))
	h, serve := verify.ServedUnverified(strp("!not a chain"), &obj, actingOn(t, "example"))
	if serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestNoChainAndNoBlocksIsServedWithNothingHandedOn(t *testing.T) {
	h, serve := verify.ServedUnverified(nil, nil, actingOn(t, "example"))
	if !serve || h != nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}

func TestABadSignatureDoesNotMatter(t *testing.T) {
	bs := stamp.Blocks{stamp.EmptyBlock, exampleBlock(t, "1", "example")}
	// The stamps carry no signature that verifies, and no key is offered: only check 9a applies.
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, bs), actingOn(t, "example"))
	if !serve || h == nil {
		t.Fatalf("serve=%v h=%v", serve, h)
	}
	if got, _ := h.Under("example"); !got[1].Named {
		t.Errorf("Under = %+v", got)
	}
}

func TestANameOutsideTheAllowedListIsNeverHandedOn(t *testing.T) {
	b, err := stamp.NewBlock(map[string][]string{"example": {"1"}, "other": {"2"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bs := stamp.Blocks{stamp.EmptyBlock, b}
	ext, err := verify.NewExtensionsAllowing([]string{"example"}, []string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, bs), ext)
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
	b, err := stamp.NewBlock(nil, []string{"influence"})
	if err != nil {
		t.Fatal(err)
	}
	bs := stamp.Blocks{stamp.EmptyBlock, b}
	h, serve := verify.ServedUnverified(servedChain(t, bs), servedBlocks(t, bs), actingOn(t, "example"))
	if !serve || h == nil {
		t.Errorf("serve=%v h=%v", serve, h)
	}
}
