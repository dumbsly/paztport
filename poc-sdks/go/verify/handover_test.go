// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"reflect"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// handOverFixture returns a hand-over for a chain of gateway then orders, whose second block names "example"
// with two items and only requires "influence".
func handOverFixture(t *testing.T, verified bool) *verify.HandOver {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{"example": {`{"note":"n1"}`, "7"}}, []string{"influence"})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := verify.NewExtensions([]string{"influence", "example"})
	if err != nil {
		t.Fatal(err)
	}
	c := stamp.Chain{{Svc: "gateway"}, {Svc: "orders"}}
	return verify.NewHandOver(verified, c, stamp.Blocks{stamp.EmptyBlock, b}, ext)
}

// TestHandOver checks each name's entries: a block that only requires an extension does not name it.
func TestHandOver(t *testing.T) {
	h := handOverFixture(t, true)
	want := map[string][]verify.StampItems{
		"example":   {{Svc: "gateway"}, {Svc: "orders", Named: true, Items: []string{`{"note":"n1"}`, "7"}}},
		"influence": {{Svc: "gateway"}, {Svc: "orders"}},
	}
	for name, entries := range want {
		got, ok := h.Under(name)
		if !ok || !reflect.DeepEqual(got, entries) {
			t.Errorf("Under(%q) = %+v, %v; want %+v", name, got, ok, entries)
		}
	}
	if got, ok := h.Under("other"); got != nil || ok {
		t.Errorf("Under(other) = %+v, %v; want nil, false", got, ok)
	}
	if got := h.Names(); !reflect.DeepEqual(got, []string{"example", "influence"}) {
		t.Errorf("Names = %v", got)
	}
	if !h.Verified() || handOverFixture(t, false).Verified() {
		t.Error("Verified is not what was passed")
	}
}

// TestHandOverIsImmutable checks that Under and Names hand out copies.
func TestHandOverIsImmutable(t *testing.T) {
	h := handOverFixture(t, true)
	got, _ := h.Under("example")
	got[1].Items[0] = "changed"
	got[0].Svc = "changed"
	got[1].Named = false
	h.Names()[0] = "changed"
	again, _ := h.Under("example")
	if again[1].Items[0] != `{"note":"n1"}` || again[0].Svc != "gateway" || !again[1].Named {
		t.Errorf("Under changed: %+v", again)
	}
	if names := h.Names(); names[0] != "example" {
		t.Errorf("Names changed: %v", names)
	}
}

// TestHandOverRefusesALengthMismatch checks that a chain and blocks of different lengths are a program fault.
func TestHandOverRefusesALengthMismatch(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHandOver did not panic")
		}
	}()
	verify.NewHandOver(true, stamp.Chain{{Svc: "a"}, {Svc: "b"}}, stamp.Blocks{stamp.EmptyBlock}, verify.Extensions{})
}
