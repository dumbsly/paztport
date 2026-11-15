// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package handover_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestExpectedReadsTheVectorForm reads null and no text as no hand-over, {} as one holding no name, and items null
// as a block that does not name the extension, each item as its canonical text.
func TestExpectedReadsTheVectorForm(t *testing.T) {
	var labelled []byte
	vectors.Load(t, "http-v4.json").Get("responses").Each(func(name string, c vectors.Node) {
		if name == "a block naming influence with a label" {
			labelled = c.Get("expected").Get("handOver").Raw()
		}
	})
	got := handover.Expected(t, labelled)
	want := []verify.StampItems{
		{Svc: "gateway"}, {Svc: "orders"},
		{Svc: "payment", Named: true, Items: []string{`{"cid":"cid-receipt-1","cls":"private","owner":"alice"}`}},
	}
	if len(got) != 1 || !slices.EqualFunc(got["influence"], want, handover.Same) {
		t.Fatalf("Expected = %+v, want influence: %+v", got, want)
	}
	for _, none := range []string{"null", ""} {
		if got := handover.Expected(t, []byte(none)); got != nil {
			t.Errorf("Expected(%q) = %+v, want nil", none, got)
		}
	}
	if empty := handover.Expected(t, []byte("{}")); empty == nil || len(empty) != 0 {
		t.Fatalf("Expected({}) = %#v, want an empty map", empty)
	}
	if got := handover.Expected(t, []byte(`{"example":[]}`)); got == nil || got["example"] == nil {
		t.Fatalf(`Expected({"example":[]}) = %#v, want example with no entry`, got)
	}
}

// TestMatchReportsEveryDifference is silent on an equal hand-over and reports each difference, without stopping
// at the first.
func TestMatchReportsEveryDifference(t *testing.T) {
	ext, err := verify.NewExtensions([]string{"example", "influence"})
	if err != nil {
		t.Fatal(err)
	}
	named, err := stamp.NewBlock(map[string][]string{"example": {"7"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := verify.NewHandOver(true, stamp.Chain{{Svc: "a"}, {Svc: "b"}}, stamp.Blocks{stamp.EmptyBlock, named}, ext)
	equal := map[string][]verify.StampItems{
		"example":   {{Svc: "a"}, {Svc: "b", Named: true, Items: []string{"7"}}},
		"influence": {{Svc: "a"}, {Svc: "b"}},
	}
	for name, c := range map[string]struct {
		h    *verify.HandOver
		want map[string][]verify.StampItems
		errs int
	}{
		"equal":          {h, equal, 0},
		"none for none":  {nil, nil, 0},
		"one where none": {h, nil, 1},
		"none where one": {nil, equal, 1},
		"an item that differs": {h, with(equal, "example", 1,
			verify.StampItems{Svc: "b", Named: true, Items: []string{"8"}}), 1},
		"named where not": {h, with(with(equal, "influence", 0,
			verify.StampItems{Svc: "a", Named: true, Items: []string{}}), "example", 0, verify.StampItems{Svc: "c"}), 2},
		"a name missing": {h, map[string][]verify.StampItems{"example": equal["example"]}, 1},
		"a name too many": {h, map[string][]verify.StampItems{
			"example": equal["example"], "influence": equal["influence"], "other": {},
		}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			r := &recorder{TB: t}
			handover.Match(r, "label", c.h, c.want)
			if len(r.errs) != c.errs {
				t.Fatalf("Match reported %q, want %d errors", r.errs, c.errs)
			}
		})
	}
}

// TestSettingsReadsTheVectorForm reads allowedExtensions null as settings that carry any name, and an array, the
// empty one included, as the only names carried.
func TestSettingsReadsTheVectorForm(t *testing.T) {
	must := func(e verify.Extensions, err error) verify.Extensions {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	for _, c := range []struct {
		actsOn, allowed string
		want            verify.Extensions
	}{
		{`[]`, `null`, verify.Extensions{}},
		{`["influence"]`, `null`, must(verify.NewExtensions([]string{"influence"}))},
		{`[]`, `[]`, must(verify.NewExtensionsAllowing(nil, []string{}))},
		{`["influence"]`, `["example","influence"]`,
			must(verify.NewExtensionsAllowing([]string{"influence"}, []string{"example", "influence"}))},
	} {
		if got := handover.Settings(t, []byte(c.actsOn), []byte(c.allowed)); !got.Equal(c.want) {
			t.Errorf("Settings(%s, %s) = %+v, want %+v", c.actsOn, c.allowed, got, c.want)
		}
	}
}

// with returns a copy of want with entry i under name replaced by e.
func with(want map[string][]verify.StampItems, name string, i int, e verify.StampItems) map[string][]verify.StampItems {
	out := map[string][]verify.StampItems{}
	for n, entries := range want {
		out[n] = slices.Clone(entries)
	}
	out[name][i] = e
	return out
}

// recorder is a testing.TB that records each error reported to it instead of failing.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
