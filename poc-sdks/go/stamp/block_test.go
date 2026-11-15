// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

func mustBlock(t *testing.T, items map[string][]string, requires []string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(items, requires)
	if err != nil {
		t.Fatalf("NewBlock: %v", err)
	}
	return b
}

func TestTheEmptyBlockCommitsToTheEmptyString(t *testing.T) {
	if got := stamp.EmptyBlock.Commit(); got != "" {
		t.Fatalf("EmptyBlock.Commit() = %q, want empty", got)
	}
	if got := string(stamp.EmptyBlock.Wire()); got != `{"items":{},"requires":[]}` {
		t.Fatalf("EmptyBlock.Wire() = %s", got)
	}
	for name, b := range map[string]stamp.Block{
		"nil":   mustBlock(t, nil, nil),
		"empty": mustBlock(t, map[string][]string{}, []string{}),
	} {
		if b.Commit() != "" || string(b.Wire()) != `{"items":{},"requires":[]}` {
			t.Errorf("the block built from %s is not the empty block: %q, %s", name, b.Commit(), b.Wire())
		}
	}
}

func TestABlockThatNamesAnExtensionWithNothingIsNotTheEmptyBlock(t *testing.T) {
	b := mustBlock(t, map[string][]string{"example": {}}, nil)
	if b.Commit() == "" {
		t.Fatal("a block naming an extension with no items commits to the empty string")
	}
	if got, ok := b.Items("example"); !ok || got == nil || len(got) != 0 {
		t.Fatalf(`Items("example") = %#v, %v, want [], true`, got, ok)
	}
	if got, ok := b.Items("influence"); ok || got != nil {
		t.Fatalf(`Items("influence") = %#v, %v, want nil, false`, got, ok)
	}
	if got, ok := mustBlock(t, nil, []string{"example"}).Items("example"); ok || got != nil {
		t.Fatalf("a name only in requires is named: %#v, %v", got, ok)
	}
}

func TestRequiresIsSortedAndANameTwiceIsRefused(t *testing.T) {
	got := mustBlock(t, nil, []string{"b", "a"}).Requires()
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("Requires() = %v, want [a b]", got)
	}
	if _, err := stamp.NewBlock(nil, []string{"a", "a"}); err == nil {
		t.Fatal("a name twice in requires is accepted")
	}
}

func TestANameThatIsNotAnExtensionNameIsRefused(t *testing.T) {
	for _, name := range []string{"", "Example", "a_b", "é", strings.Repeat("a", 33)} {
		if stamp.IsExtensionName(name) {
			t.Errorf("IsExtensionName(%q) = true", name)
		}
		if _, err := stamp.NewBlock(map[string][]string{name: {}}, nil); err == nil {
			t.Errorf("%q accepted in items", name)
		}
		if _, err := stamp.NewBlock(nil, []string{name}); err == nil {
			t.Errorf("%q accepted in requires", name)
		}
	}
	long := strings.Repeat("a", 32)
	if !stamp.IsExtensionName(long) || !stamp.IsExtensionName("a-0") {
		t.Fatal("a 32-character name or one with a digit and a hyphen is refused")
	}
	mustBlock(t, map[string][]string{long: {}}, []string{long})
}

func TestAnItemThatIsNotCanonicalTextIsRefused(t *testing.T) {
	for _, item := range []string{" 1", `{"b":1,"a":2}`, "1.0", "[1,]", "1 2", "", `"` + bs + `u0041"`} {
		if _, err := stamp.NewBlock(map[string][]string{"example": {item}}, nil); err == nil {
			t.Errorf("the item %q is accepted", item)
		}
	}
	for _, item := range []string{`{"a":2,"b":1}`, "7", `"x"`, "null", "[]"} {
		if _, err := stamp.NewBlock(map[string][]string{"example": {item}}, nil); err != nil {
			t.Errorf("the item %q is refused: %v", item, err)
		}
	}
}

func TestABlockDoesNotChangeWithWhatItWasBuiltFrom(t *testing.T) {
	items := []string{"1"}
	m := map[string][]string{"example": items}
	req := []string{"a"}
	b := mustBlock(t, m, req)
	commit, wire := b.Commit(), string(b.Wire())

	items[0] = "2"
	m["other"] = nil
	req[0] = "zzz"
	got, _ := b.Items("example")
	got[0] = "3"
	b.Requires()[0] = "yyy"
	b.Names()[0] = "xxx"

	if b.Commit() != commit || string(b.Wire()) != wire {
		t.Fatalf("the block changed: %s, %s", b.Commit(), b.Wire())
	}
	if again, _ := b.Items("example"); !slices.Equal(again, []string{"1"}) {
		t.Fatalf(`Items("example") = %v, want [1]`, again)
	}
	if !slices.Equal(b.Requires(), []string{"a"}) || !slices.Equal(b.Names(), []string{"example"}) {
		t.Fatalf("Requires() = %v, Names() = %v", b.Requires(), b.Names())
	}
}

func TestBlocksWrittenReadBack(t *testing.T) {
	b := mustBlock(t, map[string][]string{
		"zeta":    {`{"a":[1,null,true],"b":"x"}`, "7", `"s"`, "false", "[]"},
		"example": {"null"},
	}, []string{"zeta", "example"})
	tok, err := stamp.Blocks{stamp.EmptyBlock, b}.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	got, err := stamp.ReadBlocks(tok)
	if err != nil || len(got) != 2 {
		t.Fatalf("ReadBlocks = %v, %v", got, err)
	}
	if string(got[0].Wire()) != string(stamp.EmptyBlock.Wire()) || string(got[1].Wire()) != string(b.Wire()) {
		t.Fatalf("the blocks changed: %s, %s", got[0].Wire(), got[1].Wire())
	}
	wantZeta := []string{`{"a":[1,null,true],"b":"x"}`, "7", `"s"`, "false", "[]"}
	if items, ok := got[1].Items("zeta"); !ok || !slices.Equal(items, wantZeta) {
		t.Fatalf("the items of zeta = %v, %v", items, ok)
	}
	if !slices.Equal(got[1].Names(), []string{"example", "zeta"}) || got[1].Commit() != b.Commit() {
		t.Fatalf("Names() = %v", got[1].Names())
	}
}

func TestWhatIsNotAnArrayOfBlocksDoesNotRead(t *testing.T) {
	for _, wire := range []string{
		"null", "{}", `[{"items":{}}]`, `[{"items":{},"requires":[],"x":1}]`,
		`[{"items":{"example":{}},"requires":[]}]`, `[{"items":{},"requires":["b","a"]}]`,
		`[{"items":{},"requires":["a","a"]}]`, `[{"items":{},"requires":[1]}]`, "[ ]",
	} {
		if got, err := stamp.ParseBlocks([]byte(wire)); err == nil {
			t.Errorf("ParseBlocks(%s) = %v, want an error", wire, got)
		}
	}
	if got, err := stamp.ParseBlocks([]byte("[]")); err != nil || len(got) != 0 {
		t.Errorf("ParseBlocks([]) = %v, %v", got, err)
	}
}

func TestAnInheritedMemberNameIsAnOrdinaryName(t *testing.T) {
	b := mustBlock(t, map[string][]string{"constructor": {"1"}, "prototype": {}}, []string{"constructor", "prototype"})
	got, err := stamp.ParseBlocks([]byte("[" + string(b.Wire()) + "]"))
	if err != nil || len(got) != 1 {
		t.Fatalf("ParseBlocks: %v, %v", got, err)
	}
	if string(got[0].Wire()) != string(b.Wire()) || got[0].Commit() != b.Commit() || b.Commit() == "" {
		t.Fatalf("the block did not round-trip: %s", got[0].Wire())
	}
	if items, ok := got[0].Items("constructor"); !ok || !slices.Equal(items, []string{"1"}) {
		t.Fatalf(`Items("constructor") = %v, %v`, items, ok)
	}
	if _, ok := mustBlock(t, nil, nil).Items("constructor"); ok {
		t.Fatal(`the empty block names "constructor"`)
	}
}
