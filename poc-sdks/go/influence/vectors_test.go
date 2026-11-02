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
)

// TestInfluence replays v3.json's influence cases. Each case's entries, read from their wire bytes,
// normalise to the case's normalized list, byte for byte, and commit to its commitment.
func TestInfluence(t *testing.T) {
	vectors.Load(t, "v3.json").Get("influence").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			es := entries(t, c.Get("entries"))
			got, err := influence.EntriesWire(influence.Normalise(es))
			equalBytes(t, "the normalised entries", got, err, canonical(t, build(c.Get("normalized"))))
			commits(t, es, c.Get("commitment").Str())
		})
	})
}

// TestCommitInfluence replays v3.json's commitInfluence.
func TestCommitInfluence(t *testing.T) {
	c := vectors.Load(t, "v3.json").Get("commitInfluence")
	commits(t, entries(t, c.Get("entries")), c.Get("expected").Str())
}

// TestRule replays v3.json's rule cases, the owner-aware rule's truth table. A case gives each entry's
// class and owner, all the rule reads. A null destination owner is unknown, as "" is.
func TestRule(t *testing.T) {
	vectors.Load(t, "v3.json").Get("rule").Each(func(name string, c vectors.Node) {
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
			destination := ""
			if d := c.Get("destinationOwner"); !d.IsNull() {
				destination = d.Str()
			}
			if got, want := influence.PublicWriteRefused(es, destination), c.Get("refused").Bool(); got != want {
				t.Fatalf("PublicWriteRefused = %v, want %v", got, want)
			}
		})
	})
}

// TestBoundaryInfluence replays http-v3.json's boundaryInfluence. Its input entries reduce to its reduced
// list, each group's salt is the case's, and each opening, read from its body, is written back as those
// bytes and opens its sent entry exactly when the case says it does.
func TestBoundaryInfluence(t *testing.T) {
	b := vectors.Load(t, "http-v3.json").Get("boundaryInfluence")
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

// commits checks es's commitment against want.
func commits(t *testing.T, es []influence.Entry, want string) {
	t.Helper()
	got, err := influence.Commit(es)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got != want {
		t.Fatalf("Commit = %q, want %q", got, want)
	}
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
