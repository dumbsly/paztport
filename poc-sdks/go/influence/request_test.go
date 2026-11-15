// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Entries and their items' text, for the request tests.
var (
	aliceOwn     = influence.Entry{Class: influence.Private, Src: "github:acme/app#42", H: "h1", Owner: "alice"}
	aliceOwnText = `{"cls":"private","h":"h1","owner":"alice","src":"github:acme/app#42"}`
	bobs         = influence.Entry{Class: influence.Private, Src: "github:acme/app#7", H: "h3", Owner: "bob"}
	bobsText     = `{"cls":"private","h":"h3","owner":"bob","src":"github:acme/app#7"}`
	web          = influence.Entry{Class: influence.ThirdParty, Src: "web:example.com", H: "h2"}
	webText      = `{"cls":"third-party","h":"h2","src":"web:example.com"}`
	docs         = influence.Entry{Class: influence.Public, Src: "web:docs.example.org", H: "h4"}
	docsText     = `{"cls":"public","h":"h4","src":"web:docs.example.org"}`
	aLabel       = `{"cid":"cid-1","cls":"private","owner":"alice"}`
)

// named is a stamp whose block names influence with items; silent is one whose block does not name it.
func named(svc string, items ...string) verify.StampItems {
	return verify.StampItems{Svc: svc, Named: true, Items: append([]string{}, items...)}
}

func silent(svc string) verify.StampItems {
	return verify.StampItems{Svc: svc}
}

// TestReadRequestReadsEveryItemInChainOrder reads every item of every block, each block's in its order and the
// blocks in the chain's.
func TestReadRequestReadsEveryItemInChainOrder(t *testing.T) {
	r := influence.ReadRequest([]verify.StampItems{
		named("session", aliceOwnText, webText),
		named("gateway"),
		named("pi", docsText, bobsText),
	})
	if !r.Reads() || !r.EveryStampNames || r.UnreadSigner != "" {
		t.Fatalf("ReadRequest = %+v, want every item read and every stamp naming influence", r)
	}
	if want := []influence.Entry{aliceOwn, web, docs, bobs}; !slices.Equal(r.Entries, want) {
		t.Fatalf("Entries = %+v, want %+v", r.Entries, want)
	}
}

// TestReadRequestABlockThatDoesNotNameInfluence: the first stamp's block does not name influence, the second's
// holds entries. The entries still read, but not every stamp names it: the rule reads the whole chain, not only the
// caller's block, which here names it.
func TestReadRequestABlockThatDoesNotNameInfluence(t *testing.T) {
	r := influence.ReadRequest([]verify.StampItems{silent("session"), named("pi", aliceOwnText, docsText)})
	if !r.Reads() || r.EveryStampNames {
		t.Fatalf("ReadRequest = %+v, want it read with not every stamp naming influence", r)
	}
	if want := []influence.Entry{aliceOwn, docs}; !slices.Equal(r.Entries, want) {
		t.Fatalf("Entries = %+v, want %+v", r.Entries, want)
	}
}

// TestReadRequestAnItemThatIsNotAnEntryNamesItsSigner: a label under the second stamp does not read as an entry,
// and the signer of its block is the one named for the operator's log.
func TestReadRequestAnItemThatIsNotAnEntryNamesItsSigner(t *testing.T) {
	r := influence.ReadRequest([]verify.StampItems{named("session", webText), named("pi", aliceOwnText, aLabel)})
	if r.Reads() || r.UnreadSigner != "pi" {
		t.Fatalf("ReadRequest = %+v, want it unread, signed by pi", r)
	}
	if len(r.Entries) != 0 || r.EveryStampNames {
		t.Fatalf("ReadRequest = %+v: an unread request holds no entries and reaches no rule", r)
	}
}

// TestReadRequestNamesTheFirstUnreadSigner: the second and third blocks both hold an item that does not read, and
// the second's signer is the one named.
func TestReadRequestNamesTheFirstUnreadSigner(t *testing.T) {
	r := influence.ReadRequest([]verify.StampItems{
		named("session", webText),
		named("gateway", aliceOwnText, aLabel),
		named("pi", `"not an entry"`),
	})
	if r.Reads() || r.UnreadSigner != "gateway" {
		t.Fatalf("ReadRequest = %+v, want it unread, signed by gateway", r)
	}
	got := influence.Decide([]verify.StampItems{silent("session"), named("gateway", aLabel), named("pi", aLabel)},
		nil, true, "alice")
	if want := (influence.Decision{Reason: reason.InfluenceMismatch, UnreadSigner: "gateway"}); got != want {
		t.Fatalf("Decide = %+v, want %+v", got, want)
	}
}

// TestReadRequestAnUnreadItemUnderAnEmptySvc: a chain's reading allows a stamp whose svc is "", and the keyless
// check hands its block on. An item there that does not read is still unread, though its signer's name is "".
func TestReadRequestAnUnreadItemUnderAnEmptySvc(t *testing.T) {
	r := influence.ReadRequest([]verify.StampItems{named("", `"not an entry"`)})
	if r.Reads() || r.UnreadSigner != "" {
		t.Fatalf("ReadRequest = %+v, want it unread, its signer \"\"", r)
	}
	h := served(t, named("", `"not an entry"`))
	if got := influence.Items(h); got != reason.InfluenceMismatch {
		t.Fatalf("Items = %s, want INFLUENCE_MISMATCH", got)
	}
	if got := influence.Decide([]verify.StampItems{named("", aLabel)}, nil, false, "alice"); got.Reason !=
		reason.InfluenceMismatch {
		t.Fatalf("Decide = %+v, want INFLUENCE_MISMATCH", got)
	}
}

// TestReadRequestNothingHandedOn: with no stamp to read the rule cannot refuse for what it is not shown, so every
// stamp names influence, and there are no entries.
func TestReadRequestNothingHandedOn(t *testing.T) {
	for _, stamps := range [][]verify.StampItems{nil, {}} {
		r := influence.ReadRequest(stamps)
		if !r.Reads() || !r.EveryStampNames || len(r.Entries) != 0 || r.UnreadSigner != "" {
			t.Errorf("ReadRequest(%#v) = %+v, want every stamp naming influence and no entries", stamps, r)
		}
	}
}

func TestDecide(t *testing.T) {
	for _, c := range []struct {
		name   string
		stamps []verify.StampItems
		added  []influence.Entry
		write  bool
		want   influence.Decision
	}{
		{"a write, the origin's block silent, only the owner's own private entry",
			[]verify.StampItems{silent("session"), named("pi", aliceOwnText)}, nil, true,
			influence.Decision{Reason: reason.InfluenceDenied}},
		{"a read, the origin's block silent, only the owner's own private entry",
			[]verify.StampItems{silent("session"), named("pi", aliceOwnText)}, nil, false,
			influence.Decision{Reason: reason.OK}},
		{"a write, untrusted content and someone else's private data",
			[]verify.StampItems{named("session"), named("pi", webText, bobsText)}, nil, true,
			influence.Decision{Reason: reason.InfluenceDenied, EveryStampNames: true}},
		{"a write, untrusted content and the owner's own private data",
			[]verify.StampItems{named("session"), named("pi", webText, aliceOwnText)}, nil, true,
			influence.Decision{Reason: reason.OK, EveryStampNames: true}},
		{"a write, someone else's private data received, nothing untrusted added",
			[]verify.StampItems{named("session"), named("pi", bobsText)}, nil, true,
			influence.Decision{Reason: reason.OK, EveryStampNames: true}},
		{"a write, someone else's private data received, third-party content added",
			[]verify.StampItems{named("session"), named("pi", bobsText)}, []influence.Entry{web}, true,
			influence.Decision{Reason: reason.InfluenceDenied, EveryStampNames: true}},
		{"a write, an item that does not read",
			[]verify.StampItems{named("session"), named("pi", aliceOwnText, aLabel)}, nil, true,
			influence.Decision{Reason: reason.InfluenceMismatch, UnreadSigner: "pi"}},
		{"a read, an item that does not read",
			[]verify.StampItems{named("session"), named("pi", aliceOwnText, aLabel)}, nil, false,
			influence.Decision{Reason: reason.InfluenceMismatch, UnreadSigner: "pi"}},
		{"a write, an item that does not read after a silent block, untrusted content added",
			[]verify.StampItems{silent("session"), named("pi", aLabel)}, []influence.Entry{web}, true,
			influence.Decision{Reason: reason.InfluenceMismatch, UnreadSigner: "pi"}},
		{"a write, nothing handed on, the owner's own private data added",
			nil, []influence.Entry{aliceOwn}, true,
			influence.Decision{Reason: reason.OK, EveryStampNames: true}},
		{"a write, nothing handed on, third-party content and someone else's private data added",
			nil, []influence.Entry{web, bobs}, true,
			influence.Decision{Reason: reason.InfluenceDenied, EveryStampNames: true}},
		{"a read, nothing handed on, third-party content and someone else's private data added",
			nil, []influence.Entry{web, bobs}, false,
			influence.Decision{Reason: reason.OK, EveryStampNames: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := influence.Decide(c.stamps, c.added, c.write, "alice"); got != c.want {
				t.Fatalf("Decide = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestGuardedWriteRefused: a stamp that does not name influence refuses the write whatever the entries say;
// otherwise the owner-aware rule decides, over its whole truth table.
func TestGuardedWriteRefused(t *testing.T) {
	if !influence.GuardedWriteRefused(false, nil, "bob") {
		t.Error("a stamp that does not name influence, and no entries, allows the write")
	}
	if !influence.GuardedWriteRefused(false, []influence.Entry{docs}, "bob") {
		t.Error("a stamp that does not name influence, and only public entries, allows the write")
	}
	untrusted := []influence.Entry{{Class: influence.ThirdParty}, {Class: influence.LocalUntrusted}, {}}
	privates := []influence.Entry{{Class: influence.Private}, {Class: influence.Private, Owner: "alice"},
		{Class: influence.Private, Owner: "bob"}, {Class: influence.Public}}
	for _, u := range append(untrusted, influence.Entry{Class: influence.Public}) {
		for _, p := range privates {
			for _, owner := range []string{"", "alice"} {
				es := []influence.Entry{u, p}
				if got, want := influence.GuardedWriteRefused(true, es, owner),
					influence.PublicWriteRefused(es, owner); got != want {
					t.Errorf("GuardedWriteRefused(true, %+v, %q) = %v, want %v", es, owner, got, want)
				}
			}
		}
	}
}

// TestShapedOnlyByTrustedEveryStamp: a verified chain with no entries still needs every stamp to name influence.
func TestShapedOnlyByTrustedEveryStamp(t *testing.T) {
	for _, c := range []struct {
		verified, every, want bool
	}{
		{true, false, false},
		{true, true, true},
		{false, true, false},
		{false, false, false},
	} {
		if got := influence.ShapedOnlyByTrusted(c.verified, c.every, nil); got != c.want {
			t.Errorf("ShapedOnlyByTrusted(%v, %v, nil) = %v, want %v", c.verified, c.every, got, c.want)
		}
	}
}

// TestItems is influence's offline item check: INFLUENCE_MISMATCH for an item that does not read, under any
// stamp, else OK; a hand-over with nothing under influence is nothing handed on.
func TestItems(t *testing.T) {
	other, err := verify.NewExtensions([]string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		h    *verify.HandOver
		want reason.Code
	}{
		{"every item an entry", served(t, named("session"), named("pi", webText, aliceOwnText)), reason.OK},
		{"a silent block", served(t, silent("session"), named("pi", webText)), reason.OK},
		{"a label", served(t, named("session"), named("pi", aLabel)), reason.InfluenceMismatch},
		{"a label after a silent block", served(t, silent("session"), named("pi", aLabel)),
			reason.InfluenceMismatch},
		{"a hand-over that holds nothing under influence",
			verify.NewHandOver(true, stamp.Chain{{Svc: "pi"}}, stamp.Blocks{block(t, aLabel)}, other), reason.OK},
		{"no hand-over", nil, reason.OK},
	} {
		if got := influence.Items(c.h); got != c.want {
			t.Errorf("%s: Items = %s, want %s", c.name, got, c.want)
		}
	}
}

// served returns the hand-over, verified, of a chain whose stamps are signed by each of stamps' Svc, each block
// naming influence with its Items where Named, and naming nothing where not, at a service acting on influence.
func served(t *testing.T, stamps ...verify.StampItems) *verify.HandOver {
	t.Helper()
	ext, err := verify.NewExtensions([]string{influence.Name})
	if err != nil {
		t.Fatal(err)
	}
	c := make(stamp.Chain, len(stamps))
	bs := make(stamp.Blocks, len(stamps))
	for i, s := range stamps {
		c[i] = stamp.Stamp{Svc: s.Svc}
		if s.Named {
			bs[i] = block(t, s.Items...)
		}
	}
	return verify.NewHandOver(true, c, bs, ext)
}

// block returns the block naming influence with items, requiring nothing.
func block(t *testing.T, items ...string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{influence.Name: append([]string{}, items...)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
