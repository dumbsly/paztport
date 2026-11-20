// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package intent_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/intent"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestItems replays intent.json's items: ParseItem refuses an item exactly when the case's facts are null, and
// otherwise gives each fact name with the JCS text of its value.
func TestItems(t *testing.T) {
	cases := vectors.Load(t, "intent.json").Get("items")
	if cases.Len() == 0 {
		t.Fatal("intent.json has no items cases")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			f, err := intent.ParseItem(c.Get("item").Str())
			facts := c.Get("facts")
			if facts.IsNull() {
				if err == nil {
					t.Fatalf("ParseItem read the item as %v, want a refusal", f.Names())
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseItem: %v", err)
			}
			if want := facts.Names(); !slices.Equal(f.Names(), slices.Sorted(slices.Values(want))) {
				t.Fatalf("Names = %q, want %q", f.Names(), want)
			}
			for _, n := range facts.Names() {
				if got, ok := f.JSON(n); !ok || got != facts.Get(n).Str() {
					t.Errorf("JSON(%q) = %q, %t, want %q", n, got, ok, facts.Get(n).Str())
				}
			}
			if _, ok := f.JSON("absent-name"); ok {
				t.Error("JSON of a name not in the item is present")
			}
		})
	})
}

// TestRequests replays intent.json's requests: ReadRequest and Require each give the answer the case records for
// them on their own, over the hand-over the case describes.
func TestRequests(t *testing.T) {
	cases := vectors.Load(t, "intent.json").Get("requests")
	if cases.Len() == 0 {
		t.Fatal("intent.json has no requests cases")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			stamps, h := handedOver(t, c)
			needs := c.Get("needs").Strs()

			r := intent.ReadRequest(stamps)
			wantRead := reason.Code(c.Get("read").Str())
			if r.Reads() != (wantRead == reason.OK) {
				t.Errorf("Reads = %t, want read %s", r.Reads(), wantRead)
			}
			wantSigner := ""
			if u := c.Get("unreadSigner"); !u.IsNull() {
				wantSigner = u.Str()
			}
			if r.UnreadSigner != wantSigner {
				t.Errorf("UnreadSigner = %q, want %q", r.UnreadSigner, wantSigner)
			}
			if got, want := intent.Require(h, needs), reason.Code(c.Get("require").Str()); got != want {
				t.Errorf("Require = %s, want %s", got, want)
			}
		})
	})
}

// handedOver builds, from a case, the stamps ReadRequest reads and the hand-over Require reads: a service that
// acts on intent is handed one StampItems per stamp, verified or not as the case says, and one that does not has
// a hand-over that holds nothing under intent. A case whose stamps are null has no hand-over at all when the
// service acts on intent.
func handedOver(t *testing.T, c vectors.Node) ([]verify.StampItems, *verify.HandOver) {
	t.Helper()
	acts := []string{}
	if c.Get("actsOn").Bool() {
		acts = append(acts, intent.Name)
	}
	ext, err := verify.NewExtensions(acts)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Get("stamps")
	if s.IsNull() {
		if len(acts) == 1 {
			return nil, nil
		}
		return nil, verify.NewHandOver(c.Get("verified").Bool(), nil, nil, ext)
	}
	if len(acts) == 0 {
		t.Fatal("the service does not act on intent, yet the case lists stamps")
	}
	var chain stamp.Chain
	var blocks stamp.Blocks
	s.Each(func(_ string, st vectors.Node) {
		chain = append(chain, stamp.Stamp{Svc: st.Get("svc").Str()})
		var b stamp.Block
		if items := st.Get("items"); !items.IsNull() {
			b, err = stamp.NewBlock(map[string][]string{intent.Name: items.Strs()}, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		blocks = append(blocks, b)
	})
	h := verify.NewHandOver(c.Get("verified").Bool(), chain, blocks, ext)
	got, _ := h.Under(intent.Name)
	return got, h
}
