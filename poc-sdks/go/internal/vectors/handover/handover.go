// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package handover compares a hand-over with the one a vector case expects, and reads a case's extension
// settings, for the module's tests. Only tests import it. It is a package of its own because it reads verify's types, which package vectors may not, since
// the tests of packages verify imports use vectors. It reads the expected hand-over from its text in the vector
// file, with the SDK's own reader, and not through vectors, because only tests may import that harness.
package handover

import (
	"maps"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Expected reads the hand-over a vector case expects from its text in the file (a vector Node's Raw), as the
// vector files write one: null for none, or an object holding, for each name acted on, one {svc, items} per stamp
// in chain order, items null where the stamp's block does not name the extension. It returns nil for null or for
// no text, a hand-over the case does not give, and otherwise the entries per name, an empty map for {}, each item
// the canonical text of its JSON value, as the core hands items over. It fails t on text of any other shape.
func Expected(t testing.TB, text []byte) map[string][]verify.StampItems {
	t.Helper()
	if len(text) == 0 {
		return nil
	}
	v, err := json.ReadFile(text)
	if err != nil {
		t.Fatalf("handover: the expected hand-over: %v", err)
	}
	if v.Kind() == json.KindNull {
		return nil
	}
	if v.Kind() != json.KindObject {
		t.Fatalf("handover: the expected hand-over is %v, not an object or null", v.Kind())
	}
	want := map[string][]verify.StampItems{}
	for _, m := range v.Members() {
		if m.Value.Kind() != json.KindArray {
			t.Fatalf("handover: the entries of %q are %v, not an array", m.Name, m.Value.Kind())
		}
		entries := []verify.StampItems{}
		for _, e := range m.Value.Items() {
			entries = append(entries, entry(t, m.Name, e))
		}
		want[m.Name] = entries
	}
	return want
}

// entry reads one {svc, items} of the entries under name.
func entry(t testing.TB, name string, e json.Value) verify.StampItems {
	t.Helper()
	if err := json.Exactly(e, []string{"items", "svc"}, nil); err != nil {
		t.Fatalf("handover: an entry of %q: %v", name, err)
	}
	svc, _ := json.Field(e, "svc")
	items, _ := json.Field(e, "items")
	if svc.Kind() != json.KindString || (items.Kind() != json.KindNull && items.Kind() != json.KindArray) {
		t.Fatalf("handover: an entry of %q is not {svc: string, items: array or null}", name)
	}
	out := verify.StampItems{Svc: svc.Str()}
	if items.Kind() == json.KindArray {
		out.Named, out.Items = true, []string{}
		for _, item := range items.Items() {
			text, err := json.Wire(item)
			if err != nil {
				t.Fatalf("handover: an item of %q has no canonical text: %v", name, err)
			}
			out.Items = append(out.Items, string(text))
		}
	}
	return out
}

// Match reports, as errors of t each prefixed with label, every difference between h and want: with a nil want, h
// must be nil; otherwise h must hold exactly want's names, and under each the entries want gives. It does not ask
// whether h was verified, which is the caller's to say.
func Match(t testing.TB, label string, h *verify.HandOver, want map[string][]verify.StampItems) {
	t.Helper()
	if want == nil {
		if h != nil {
			t.Errorf("%s: handed over %q, want nothing", label, h.Names())
		}
		return
	}
	if h == nil {
		t.Errorf("%s: handed over nothing, want %q", label, slices.Sorted(maps.Keys(want)))
		return
	}
	if names := slices.Sorted(maps.Keys(want)); !slices.Equal(h.Names(), names) {
		t.Errorf("%s: the hand-over holds %q, want %q", label, h.Names(), names)
	}
	for _, name := range slices.Sorted(maps.Keys(want)) {
		under, ok := h.Under(name)
		if !ok || !slices.EqualFunc(under, want[name], Same) {
			t.Errorf("%s: Under(%s) = %+v, %t, want %+v", label, name, under, ok, want[name])
		}
	}
}

// Same reports whether two entries are equal; an empty and a nil Items are the same list, Named telling them
// apart.
func Same(a, b verify.StampItems) bool {
	return a.Svc == b.Svc && a.Named == b.Named && slices.Equal(a.Items, b.Items)
}

// Settings returns the extension settings a vector case gives, from the texts of its actsOn and allowedExtensions
// members (a vector Node's Raw): actsOn an array of names, and allowedExtensions null for settings that carry any
// name, or the array of the only names carried. It fails t on text of any other shape, and on settings the SDK
// refuses.
func Settings(t testing.TB, actsOn, allowed []byte) verify.Extensions {
	t.Helper()
	acts, listed := names(t, "actsOn", actsOn), names(t, "allowedExtensions", allowed)
	var e verify.Extensions
	var err error
	if listed == nil {
		e, err = verify.NewExtensions(acts)
	} else {
		e, err = verify.NewExtensionsAllowing(acts, listed)
	}
	if err != nil {
		t.Fatalf("handover: the case's extension settings: %v", err)
	}
	return e
}

// names reads an array of names from text, or nil for null; what names the member, for a failure.
func names(t testing.TB, what string, text []byte) []string {
	t.Helper()
	v, err := json.ReadFile(text)
	if err != nil {
		t.Fatalf("handover: %s: %v", what, err)
	}
	if v.Kind() == json.KindNull {
		return nil
	}
	if v.Kind() != json.KindArray {
		t.Fatalf("handover: %s is %v, not an array or null", what, v.Kind())
	}
	out := []string{}
	for _, n := range v.Items() {
		if n.Kind() != json.KindString {
			t.Fatalf("handover: %s holds %v, not a name", what, n.Kind())
		}
		out = append(out, n.Str())
	}
	return out
}
