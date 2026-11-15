// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// The extension's sections of v4.json, its member influence, and http-v4.json's boundaryInfluence are replayed
// here; offline replays influence.recordedCall. As spec/README.md's Conformance section says of an implementation
// that does not implement the MCP profile, influence.response and the influence.request cases whose served is not
// empty are not replayed: they record the extension over MCP, what a client adds for a response whose every stamp
// is the server's and what a server decides with the classes it served in its session.

// TestEntryVectors replays v4.json's influence.entries: ParseEntry reads the item's text exactly when the case
// says it reads.
func TestEntryVectors(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("influence").Get("entries")
	if cases.Len() != 17 {
		t.Fatalf("v4.json has %d influence.entries cases, want 17", cases.Len())
	}
	readsBoth(t, cases, func(item string) error {
		_, err := influence.ParseEntry(item)
		return err
	})
}

// TestLabelVectors replays v4.json's influence.labels: ParseLabel reads the item's text exactly when the case
// says it reads.
func TestLabelVectors(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("influence").Get("labels")
	if cases.Len() != 9 {
		t.Fatalf("v4.json has %d influence.labels cases, want 9", cases.Len())
	}
	readsBoth(t, cases, func(item string) error {
		_, err := influence.ParseLabel(item)
		return err
	})
}

// readsBoth runs read over each case's item, as its JCS text, against the case's reads, and checks the section
// holds items that read and items that do not.
func readsBoth(t *testing.T, cases vectors.Node, read func(item string) error) {
	t.Helper()
	seen := map[bool]bool{}
	cases.Each(func(_ string, c vectors.Node) {
		seen[c.Get("reads").Bool()] = true
	})
	if !seen[true] || !seen[false] {
		t.Fatalf("the section's items all read, or none does: %v", seen)
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			err := read(string(canonical(t, build(c.Get("item")))))
			if want := c.Get("reads").Bool(); (err == nil) != want {
				t.Fatalf("read it: %t (%v), want %t", err == nil, err, want)
			}
		})
	})
}

// TestRule replays v4.json's influence.rule, the owner-aware rule's truth table. A case gives each entry's
// class and owner, all the rule reads. A null destination owner is unknown, as "" is.
func TestRule(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("influence").Get("rule")
	if cases.Len() != 13 {
		t.Fatalf("v4.json has %d influence.rule cases, want 13", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			var es []influence.Entry
			c.Get("influence").Each(func(_ string, f vectors.Node) {
				e := influence.Entry{Class: class(t, f.Get("cls").Str())}
				if f.Has("owner") {
					e.Owner = f.Get("owner").Str()
				}
				es = append(es, e)
			})
			if got, want := influence.PublicWriteRefused(es, owner(c)), c.Get("refused").Bool(); got != want {
				t.Fatalf("PublicWriteRefused = %v, want %v", got, want)
			}
		})
	})
}

// TestRequestVectors replays v4.json's influence.request cases whose served is empty: Decide over the items
// handed on, with nothing added, gives the case's reason, and, where the case gives one, its everyStampNames. A
// case gives null for everyStampNames only beside INFLUENCE_MISMATCH, where no rule is reached; the replay checks
// that from the file rather than assuming it. A stamp whose items are null is one whose block does not name
// influence, as the hand-over gives it.
func TestRequestVectors(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("influence").Get("request")
	replayed := 0
	occur := map[reason.Code]bool{}
	cases.Each(func(name string, c vectors.Node) {
		if c.Get("served").Len() != 0 {
			return // the MCP profile's: see the note at the top of this file
		}
		replayed++
		occur[reason.Code(c.Get("expected").Get("reason").Str())] = true
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			var stamps []verify.StampItems
			c.Get("stamps").Each(func(_ string, st vectors.Node) {
				s := verify.StampItems{Svc: st.Get("svc").Str()}
				if items := st.Get("items"); !items.IsNull() {
					s.Named, s.Items = true, []string{}
					items.Each(func(_ string, item vectors.Node) {
						s.Items = append(s.Items, string(canonical(t, build(item))))
					})
				}
				stamps = append(stamps, s)
			})
			got := influence.Decide(stamps, nil, c.Get("write").Bool(), owner(c))
			want := c.Get("expected")
			if w := reason.Code(want.Get("reason").Str()); got.Reason != w {
				t.Fatalf("Decide = %+v, want the reason %s", got, w)
			}
			every := want.Get("everyStampNames")
			if every.IsNull() {
				if got.Reason != reason.InfluenceMismatch {
					t.Fatalf("the case gives no everyStampNames beside %s", got.Reason)
				}
				if got.UnreadSigner == "" {
					t.Fatalf("Decide = %+v names no signer for the item that does not read", got)
				}
				return
			}
			if got.EveryStampNames != every.Bool() {
				t.Fatalf("Decide = %+v, want everyStampNames %t", got, every.Bool())
			}
		})
	})
	if replayed != 12 {
		t.Fatalf("v4.json has %d influence.request cases whose served is empty, want 12", replayed)
	}
	for _, code := range []reason.Code{reason.OK, reason.InfluenceDenied, reason.InfluenceMismatch} {
		if !occur[code] {
			t.Errorf("no replayed influence.request case expects %s", code)
		}
	}
}

// owner returns case c's destinationOwner, "" where it is null.
func owner(c vectors.Node) string {
	if d := c.Get("destinationOwner"); !d.IsNull() {
		return d.Str()
	}
	return ""
}

// TestBoundaryInfluence replays http-v4.json's boundaryInfluence. Its input entries reduce to its reduced
// list, each group's salt is the case's, and each opening, read from its body, is written back as those
// bytes and opens its sent entry exactly when the case says it does.
func TestBoundaryInfluence(t *testing.T) {
	b := vectors.Load(t, "http-v4.json").Get("boundaryInfluence")
	key := decode(t, b.Get("key").Str())
	rid, rcv := b.Get("rid").Str(), b.Get("rcv").Str()

	reduced, err := influence.Reduce(entries(t, b.Get("input")), key, rid, rcv, b.Get("egress").Str())
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	got, err := influence.EntriesWire(reduced)
	equalBytes(t, "the reduced entries", got, err, canonical(t, build(b.Get("reduced"))))

	salts := b.Get("salts")
	if salts.Len() != len(reduced) {
		t.Errorf("the case gives %d salts for %d groups", salts.Len(), len(reduced))
	}
	salts.Each(func(i string, s vectors.Node) {
		t.Run("salt "+i, func(t *testing.T) {
			s := s.With(t)
			owner := ""
			if s.Has("owner") {
				owner = s.Get("owner").Str()
			}
			salt, err := influence.Salt(key, rid, rcv, class(t, s.Get("cls").Str()), owner)
			if err != nil {
				t.Fatalf("Salt: %v", err)
			}
			if got, want := b64.Encode(salt), s.Get("salt").Str(); got != want {
				t.Fatalf("Salt = %s, want %s", got, want)
			}
		})
	})

	b.Get("openings").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			sent := entries(t, c.Get("sent"))[0]
			body, err := hex.DecodeString(c.Get("body").Str())
			if err != nil {
				t.Fatalf("body: %v", err)
			}
			if want := canonical(t, build(c.Get("opening"))); !bytes.Equal(body, want) {
				t.Fatalf("the case's body is not its opening's wire bytes")
			}
			o, err := influence.ParseOpening(body)
			if err != nil {
				t.Fatalf("ParseOpening: %v", err)
			}
			got, err := o.Wire()
			equalBytes(t, "the opening", got, err, body)
			if got, want := influence.Opens(sent, o), c.Get("opens").Bool(); got != want {
				t.Fatalf("Opens = %v, want %v", got, want)
			}
		})
	})
}

// entries reads vector node n, an entry or a list of them, from its wire bytes, failing t if
// ParseEntries refuses them.
func entries(t *testing.T, n vectors.Node) []influence.Entry {
	t.Helper()
	v := build(n)
	if n.Kind() == vectors.Object {
		v = json.Arr(v)
	}
	es, err := influence.ParseEntries(canonical(t, v))
	if err != nil {
		t.Fatalf("ParseEntries: %v", err)
	}
	return es
}

// class returns the class whose wire name is s, failing t if there is none.
func class(t *testing.T, s string) influence.Class {
	t.Helper()
	c, ok := influence.ParseClass(s)
	if !ok {
		t.Fatalf("%q is not an influence class", s)
	}
	return c
}

// build returns the Value vector node n describes, members in the node's order.
func build(n vectors.Node) json.Value {
	switch n.Kind() {
	case vectors.Bool:
		return json.B(n.Bool())
	case vectors.Number:
		return json.I(n.Int())
	case vectors.String:
		return json.S(n.Str())
	case vectors.Array:
		var items []json.Value
		n.Each(func(_ string, item vectors.Node) { items = append(items, build(item)) })
		return json.Arr(items...)
	case vectors.Object:
		var members []json.Member
		n.Each(func(name string, v vectors.Node) { members = append(members, json.Member{Name: name, Value: build(v)}) })
		return json.Obj(members...)
	}
	return json.Null()
}

// canonical returns v's wire bytes, failing t if the writer refuses it.
func canonical(t *testing.T, v json.Value) []byte {
	t.Helper()
	b, err := json.Wire(v)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
}

// equalBytes checks what a writer gave against want.
func equalBytes(t *testing.T, what string, got []byte, err error, want []byte) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s can't be written: %v", what, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: wrote %s, want %s", what, got, want)
	}
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.Decode(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return b
}
