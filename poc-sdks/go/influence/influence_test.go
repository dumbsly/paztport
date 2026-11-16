// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
)

// Text the tests build from code points and bytes, so that no escape in this file can turn into the
// character it names when the file is written.
var (
	grinning     = string(rune(0x1F600)) // U+1F600: UTF-16 D83D DE00
	hebrew       = string(rune(0xFB33))  // U+FB33: UTF-16 FB33, after D83D though its code point is lower
	nonCharacter = string(rune(0xFFFE))
	notUTF8      = string([]byte{0xFF})
	surrogate    = string([]byte{0xED, 0xA0, 0x80}) // the WTF-8 bytes of a lone U+D800
)

func TestParseClass(t *testing.T) {
	classes := []influence.Class{influence.ThirdParty, influence.Private, influence.Public, influence.LocalUntrusted}
	for _, c := range classes {
		if got, ok := influence.ParseClass(string(c)); !ok || got != c {
			t.Errorf("ParseClass(%q) = %q, %v", c, got, ok)
		}
	}
	for _, s := range []string{"", "Private", "third_party", "secret"} {
		if _, ok := influence.ParseClass(s); ok {
			t.Errorf("ParseClass(%q) knows it", s)
		}
	}
}

// TestNormaliseUTF16Order sorts each text field by UTF-16 code units, where U+1F600 comes before U+FB33,
// not by Go's byte order, where it comes after.
func TestNormaliseUTF16Order(t *testing.T) {
	base := influence.Entry{Class: influence.Public, Src: "s", H: "h", CID: "c", HasCID: true, Owner: "o"}
	for _, field := range []struct {
		name string
		set  func(e *influence.Entry, s string)
	}{
		{"h", func(e *influence.Entry, s string) { e.H = s }},
		{"src", func(e *influence.Entry, s string) { e.Src = s }},
		{"cid", func(e *influence.Entry, s string) { e.CID = s }},
		{"owner", func(e *influence.Entry, s string) { e.Owner = s }},
	} {
		t.Run(field.name, func(t *testing.T) {
			first, second := base, base
			field.set(&first, grinning+"a")
			field.set(&second, hebrew+"a")
			got := influence.Normalise([]influence.Entry{second, first})
			if !slices.Equal(got, []influence.Entry{first, second}) {
				t.Fatalf("Normalise = %+v, want U+1F600 first", got)
			}
		})
	}
}

// TestNormaliseOrder pins the order of the fields: h, then cls, then src, then cid, then owner, with an
// absent cid or owner first.
func TestNormaliseOrder(t *testing.T) {
	sorted := []influence.Entry{
		{Class: influence.Public, Src: "z", H: "a"},
		{Class: influence.Private, Src: "c", H: "b"}, // cls decides before src
		{Class: influence.Public, Src: "a", H: "b"},
		{Class: influence.Public, Src: "b", H: "b"},
		{Class: influence.Public, Src: "b", H: "b", Owner: "a"},
		{Class: influence.Public, Src: "b", H: "b", HasCID: true},
		{Class: influence.Public, Src: "b", H: "b", CID: "a", HasCID: true},
		{Class: influence.Public, Src: "b", H: "b", CID: "a", HasCID: true, Owner: "a"},
		{Class: influence.Public, Src: "b", H: "b", CID: "a", HasCID: true, Owner: "b"},
	}
	reversed := slices.Clone(sorted)
	slices.Reverse(reversed)
	if got := influence.Normalise(reversed); !slices.Equal(got, sorted) {
		t.Fatalf("Normalise =\n%+v\nwant\n%+v", got, sorted)
	}
}

// TestNormaliseDuplicates drops entries whose wire forms are equal and keeps every other.
func TestNormaliseDuplicates(t *testing.T) {
	e := influence.Entry{Class: influence.Private, Src: "s", H: "h"}
	owned := e
	owned.Owner = "alice"
	emptyCID := e
	emptyCID.HasCID = true
	unwritten := e
	unwritten.CID = "ignored" // HasCID is unset, so this cid is not part of the entry
	got := influence.Normalise([]influence.Entry{owned, e, emptyCID, e, unwritten, owned})
	if want := []influence.Entry{e, owned, emptyCID}; !slices.Equal(got, want) {
		t.Fatalf("Normalise = %+v, want %+v", got, want)
	}
}

// TestNormaliseCopies leaves its argument as it was.
func TestNormaliseCopies(t *testing.T) {
	es := []influence.Entry{{Class: influence.Public, Src: "s", H: "b"}, {Class: influence.Public, Src: "s", H: "a"}}
	before := slices.Clone(es)
	influence.Normalise(es)
	if !slices.Equal(es, before) {
		t.Fatalf("Normalise changed its argument to %+v", es)
	}
}

// TestNormaliseInvalidText gives one order for text that is not UTF-8, whatever order it comes in, though
// the UTF-16 order sees both bytes as U+FFFD. Nothing writes such text.
func TestNormaliseInvalidText(t *testing.T) {
	a := influence.Entry{Class: influence.Public, Src: "s", H: string([]byte{0xFE})}
	b := influence.Entry{Class: influence.Public, Src: "s", H: notUTF8}
	one := influence.Normalise([]influence.Entry{a, b})
	other := influence.Normalise([]influence.Entry{b, a})
	if len(one) != 2 || !slices.Equal(one, other) {
		t.Fatalf("Normalise gave %+v and %+v", one, other)
	}
	if b, err := influence.EntriesWire(one); err == nil {
		t.Fatalf("EntriesWire wrote text that is not UTF-8 as %s", b)
	}
}

// TestEmptyCID keeps a present, empty cid through reading, normalising and writing: it is not an absent
// one, alone or in a block.
func TestEmptyCID(t *testing.T) {
	item := `{"cid":"","cls":"public","h":"h","src":"s"}`
	e, err := influence.ParseEntry(item)
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if !e.HasCID || e.CID != "" {
		t.Fatalf("read %+v, want a present empty cid", e)
	}
	es := []influence.Entry{e}
	got, err := influence.EntriesWire(influence.Normalise(es))
	equalBytes(t, "the entries", got, err, []byte(`[`+item+`]`))

	absent := es[0]
	absent.HasCID = false
	one, err := influence.RequestBlock(es, nil)
	if err != nil {
		t.Fatalf("RequestBlock: %v", err)
	}
	other, err := influence.RequestBlock([]influence.Entry{absent}, nil)
	if err != nil {
		t.Fatalf("RequestBlock: %v", err)
	}
	if one.Commit() == other.Commit() {
		t.Fatal("an empty cid and no cid commit alike")
	}
}

func TestEntriesWire(t *testing.T) {
	got, err := influence.EntriesWire(nil)
	equalBytes(t, "no entries", got, err, []byte(`[]`))

	// The order is the one given, and an empty Owner is no owner.
	got, err = influence.EntriesWire([]influence.Entry{
		{Class: influence.Public, Src: "s", H: "z"},
		{Class: influence.Private, Src: "s", H: "a", CID: "c", HasCID: true, Owner: "alice"},
	})
	equalBytes(t, "the entries", got, err,
		[]byte(`[{"cls":"public","h":"z","src":"s"},{"cid":"c","cls":"private","h":"a","owner":"alice","src":"s"}]`))

	for _, c := range []struct {
		name string
		e    influence.Entry
	}{
		{"an unknown class", influence.Entry{Class: "secret", Src: "s", H: "h"}},
		{"no class", influence.Entry{Src: "s", H: "h"}},
		{"src not UTF-8", influence.Entry{Class: influence.Public, Src: notUTF8, H: "h"}},
		{"h a lone surrogate", influence.Entry{Class: influence.Public, Src: "s", H: surrogate}},
		{"cid a noncharacter", influence.Entry{Class: influence.Public, Src: "s", H: "h", CID: nonCharacter, HasCID: true}},
		{"owner a noncharacter", influence.Entry{Class: influence.Public, Src: "s", H: "h", Owner: nonCharacter}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if b, err := influence.EntriesWire([]influence.Entry{c.e}); err == nil {
				t.Fatalf("EntriesWire wrote %s", b)
			}
			if b, err := influence.RequestBlock([]influence.Entry{c.e}, nil); err == nil {
				t.Fatalf("RequestBlock wrote %s", b.Wire())
			}
		})
	}
}

func TestNewLabel(t *testing.T) {
	l := influence.NewLabel(influence.Private, "alice")
	if l.Class != influence.Private || l.Owner != "alice" {
		t.Fatalf("NewLabel = %+v", l)
	}
	if cid := decode(t, l.CID); len(cid) != 16 {
		t.Fatalf("the cid is %d bytes, want 16", len(cid))
	}
	if other := influence.NewLabel(influence.Private, "alice"); other.CID == l.CID {
		t.Fatal("two labels share a cid")
	}
	if l := influence.NewLabel(influence.Public, ""); l.Owner != "" {
		t.Fatalf("NewLabel gave an owner %q", l.Owner)
	}
}

func TestLabelEntry(t *testing.T) {
	l := influence.Label{Class: influence.Private, CID: "", Owner: "alice"}
	want := influence.Entry{Class: influence.Private, Src: "http:orders", H: "rh", CID: "", HasCID: true, Owner: "alice"}
	if got := l.Entry("http:orders", "rh"); got != want {
		t.Fatalf("Entry = %+v, want %+v", got, want)
	}
}

// TestPublicWriteRefusedUnknownClass fails closed on a class built by hand: it is untrusted content and
// someone else's private data at once.
func TestPublicWriteRefusedUnknownClass(t *testing.T) {
	odd := influence.Entry{Class: "secret", Owner: "alice"}
	if !influence.PublicWriteRefused([]influence.Entry{odd}, "alice") {
		t.Error("an unknown class alone is allowed")
	}
	if !influence.PublicWriteRefused([]influence.Entry{odd, {Class: influence.Private, Owner: "bob"}}, "alice") {
		t.Error("an unknown class does not count as untrusted")
	}
	if !influence.PublicWriteRefused([]influence.Entry{{Class: influence.ThirdParty}, {Class: "secret"}}, "alice") {
		t.Error("an unknown class does not count as private data")
	}
	if influence.PublicWriteRefused(nil, "") {
		t.Error("no influence refuses a write")
	}
}

// TestShapedOnlyByTrusted replays the trusted-record table: a record may be written only from a request
// whose chain passed at this hop with every stamp naming influence, and whose influence holds nothing untrusted.
func TestShapedOnlyByTrusted(t *testing.T) {
	private := influence.Entry{Class: influence.Private, Owner: "bob"}
	public := influence.Entry{Class: influence.Public}
	for _, c := range []struct {
		name            string
		verified, every bool
		es              []influence.Entry
		want            bool
	}{
		{"not verified, no entries", false, true, nil, false},
		{"not verified, a stamp not naming influence, no entries", false, false, nil, false},
		{"not verified, only private", false, true, []influence.Entry{private}, false},
		{"not verified, third-party", false, true, []influence.Entry{{Class: influence.ThirdParty}}, false},
		{"a stamp not naming influence, no entries", true, false, nil, false},
		{"a stamp not naming influence, only private", true, false, []influence.Entry{private, public}, false},
		{"third-party", true, true, []influence.Entry{public, {Class: influence.ThirdParty}}, false},
		{"local-untrusted", true, true, []influence.Entry{{Class: influence.LocalUntrusted}, private}, false},
		{"an unknown class", true, true, []influence.Entry{{Class: "secret"}}, false},
		{"no entries", true, true, nil, true},
		{"private and public with owners", true, true,
			[]influence.Entry{private, public, {Class: influence.Private}}, true},
	} {
		if got := influence.ShapedOnlyByTrusted(c.verified, c.every, c.es); got != c.want {
			t.Errorf("%s: ShapedOnlyByTrusted = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRequestBlock: a hop with nothing to add names influence with [], which is not the empty block; one with
// entries holds each entry's text in the order given, and the requires it is given.
func TestRequestBlock(t *testing.T) {
	none, err := influence.RequestBlock(nil, nil)
	if err != nil {
		t.Fatalf("RequestBlock: %v", err)
	}
	if items, ok := none.Items(influence.Name); !ok || len(items) != 0 {
		t.Fatalf("RequestBlock(nil, nil) names influence with %v, %t; want [], true", items, ok)
	}
	if none.Commit() == "" || string(none.Wire()) != `{"items":{"influence":[]},"requires":[]}` {
		t.Fatalf("RequestBlock(nil, nil) = %s, the empty block or another", none.Wire())
	}
	b, err := influence.RequestBlock([]influence.Entry{web, aliceOwn, web}, []string{influence.Name})
	if err != nil {
		t.Fatalf("RequestBlock: %v", err)
	}
	if items, _ := b.Items(influence.Name); !slices.Equal(items, []string{webText, aliceOwnText, webText}) {
		t.Fatalf("the items are %v, want the entries' text in the order given", items)
	}
	if got := b.Requires(); !slices.Equal(got, []string{influence.Name}) {
		t.Fatalf("Requires = %v, want [influence]", got)
	}
	if _, err := influence.RequestBlock(nil, []string{"Influence"}); err == nil {
		t.Fatal("RequestBlock required a name that is not an extension name")
	}
}

// TestResponseBlock: a block with a label requires influence, added when the caller left it out and kept once
// when it did not; a block with no label names influence with [] and requires only what it is given.
func TestResponseBlock(t *testing.T) {
	label := influence.Label{Class: influence.Private, CID: "cid-1", Owner: "alice"}
	for _, c := range []struct {
		name     string
		labels   []influence.Label
		requires []string
		wire     string
	}{
		{"a label", []influence.Label{label}, nil,
			`{"items":{"influence":[` + aLabel + `]},"requires":["influence"]}`},
		{"a label, influence required already", []influence.Label{label}, []string{"influence", "example"},
			`{"items":{"influence":[` + aLabel + `]},"requires":["example","influence"]}`},
		{"a label, another name required", []influence.Label{label}, []string{"example"},
			`{"items":{"influence":[` + aLabel + `]},"requires":["example","influence"]}`},
		{"no label", nil, nil, `{"items":{"influence":[]},"requires":[]}`},
		{"no label, another name required", []influence.Label{}, []string{"example"},
			`{"items":{"influence":[]},"requires":["example"]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := slices.Clone(c.requires)
			b, err := influence.ResponseBlock(c.labels, c.requires)
			if err != nil {
				t.Fatalf("ResponseBlock: %v", err)
			}
			if got := string(b.Wire()); got != c.wire {
				t.Fatalf("ResponseBlock = %s, want %s", got, c.wire)
			}
			if !slices.Equal(c.requires, before) {
				t.Fatalf("ResponseBlock changed its requires to %v", c.requires)
			}
		})
	}
	for _, l := range []influence.Label{{Class: "secret", CID: "c"}, {Class: influence.Public, CID: notUTF8},
		{Class: influence.Public, CID: "c", Owner: nonCharacter}} {
		if b, err := influence.ResponseBlock([]influence.Label{l}, nil); err == nil {
			t.Errorf("ResponseBlock(%+q) wrote %s", l, b.Wire())
		}
	}
}

// TestParseEntry reads one item's text as an entry, and refuses text that is not canonical as well as an item
// that is not an entry, naming the member where the entry's schema breaks and never quoting the input.
func TestParseEntry(t *testing.T) {
	e, err := influence.ParseEntry(`{"cid":"","cls":"private","h":"h1","owner":"alice","src":"github:acme/app#42"}`)
	want := aliceOwn
	want.HasCID = true
	if err != nil || e != want {
		t.Fatalf("ParseEntry = %+v, %v; want %+v", e, err, want)
	}
	for _, item := range []string{
		`{"cls":"third-party", "h":"secret","src":"web:example.com"}`,
		`{"src":"web:example.com","cls":"third-party","h":"secret"}`,
		`{"cls":"third-party","h":"secret","src":"web:example.com"} `,
		`[` + webText + `]`,
		aLabel,
		``,
		`{"cls":"third-party","h":"h2","src":"web:example.com"}{}`,
	} {
		if e, err := influence.ParseEntry(item); err == nil {
			t.Errorf("ParseEntry(%q) = %+v", item, e)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("the refusal %q quotes the input", err)
		}
	}
	for _, c := range []struct{ name, item, says string }{
		{"no h", `{"cls":"public","src":"s"}`, `"h" is missing`},
		{"no cls", `{"h":"h","src":"s"}`, `"cls" is missing`},
		{"no src", `{"cls":"public","h":"h"}`, `"src" is missing`},
		{"another member", `{"cls":"public","h":"h","secret":"s","src":"s"}`, "member 2 is not one"},
		{"an unknown class", `{"cls":"secret","h":"h","src":"s"}`, `"cls" is not an influence class`},
		{"a class that is not a string", `{"cls":1,"h":"h","src":"s"}`, `"cls" is not a string`},
		{"src not a string", `{"cls":"public","h":"h","src":null}`, `"src" is not a string`},
		{"h not a string", `{"cls":"public","h":["secret"],"src":"s"}`, `"h" is not a string`},
		{"cid not a string", `{"cid":null,"cls":"public","h":"h","src":"s"}`, `"cid" is not a string`},
		{"an empty owner", `{"cls":"private","h":"h","owner":"","src":"s"}`, `"owner" is empty`},
		{"owner not a string", `{"cls":"private","h":"h","owner":7,"src":"s"}`, `"owner" is not a string`},
		{"members out of order", `{"src":"s","cls":"public","h":"h"}`, "canonical"},
		{"empty text", ``, "parse"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := influence.ParseEntry(c.item)
			if err == nil {
				t.Fatal("ParseEntry read it")
			}
			msg := err.Error()
			const prefix = "paztport influence: malformed influence entry: "
			if !strings.HasPrefix(msg, prefix) || !strings.Contains(msg, c.says) {
				t.Fatalf("the refusal %q does not say %q", msg, c.says)
			}
			if strings.Contains(msg, "secret") {
				t.Fatalf("the refusal %q quotes the input", msg)
			}
		})
	}
}

// TestParseLabel reads one item's text as a label, and refuses text that is not canonical as well as an item
// that is not a label, naming the member where the schema breaks and never quoting the input.
func TestParseLabel(t *testing.T) {
	l, err := influence.ParseLabel(aLabel)
	if want := (influence.Label{Class: influence.Private, CID: "cid-1", Owner: "alice"}); err != nil || l != want {
		t.Fatalf("ParseLabel = %+v, %v; want %+v", l, err, want)
	}
	for _, item := range []string{
		`{"cid":"cid-1", "cls":"private"}`,
		`{"cls":"private","cid":"cid-1"}`,
		`[{"cid":"cid-1","cls":"private"}]`,
		webText,
		`null`,
	} {
		if l, err := influence.ParseLabel(item); err == nil {
			t.Errorf("ParseLabel(%q) = %+v", item, l)
		}
	}
	for _, c := range []struct{ name, item, says string }{
		{"no cid", `{"cls":"public"}`, `"cid" is missing`},
		{"an entry's member", `{"cid":"c","cls":"public","src":"secret"}`, "member 2 is not one"},
		{"an unknown class", `{"cid":"c","cls":"secret"}`, `"cls" is not an influence class`},
		{"an empty owner", `{"cid":"c","cls":"private","owner":""}`, `"owner" is empty`},
		{"cid not a string", `{"cid":1,"cls":"private"}`, `"cid" is not a string`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := influence.ParseLabel(c.item)
			if err == nil {
				t.Fatal("ParseLabel read it")
			}
			if msg := err.Error(); !strings.Contains(msg, c.says) || strings.Contains(msg, "secret") {
				t.Fatalf("the refusal %q does not say %q, or quotes the input", msg, c.says)
			}
		})
	}
}

// boundary is a reduction to work with: a key, a request, a partner and influence holding an owned
// group of two, a third-party entry and private data with no owner.
var boundary = struct {
	key           []byte
	rid, rcv, egr string
	es            []influence.Entry
}{
	key: bytes.Repeat([]byte{7}, influence.KeyLength),
	rid: "rid-1", rcv: "psp", egr: "payment",
	es: []influence.Entry{
		{Class: influence.Private, Src: "http:orders", H: "h-order-1", CID: "cid-order-1", HasCID: true, Owner: "alice"},
		{Class: influence.Private, Src: "http:cards", H: "h-card-1", Owner: "alice"},
		{Class: influence.ThirdParty, Src: "ticket:t-1", H: "h-ticket-1"},
		{Class: influence.Private, Src: "http:ledger", H: "h-ledger-1"},
	},
}

// reduce reduces es under the boundary's key, request, partner and egress, failing t if Reduce refuses.
func reduce(t *testing.T, es []influence.Entry, rid string) []influence.Entry {
	t.Helper()
	sent, err := influence.Reduce(es, boundary.key, rid, boundary.rcv, boundary.egr)
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	return sent
}

func TestReduce(t *testing.T) {
	sent := reduce(t, boundary.es, boundary.rid)
	if len(sent) != 3 {
		t.Fatalf("Reduce sent %d entries for 3 groups", len(sent))
	}
	if !slices.Equal(sent, influence.Normalise(sent)) {
		t.Error("the sent list is not normalised")
	}
	wire, err := influence.EntriesWire(sent)
	if err != nil {
		t.Fatalf("EntriesWire: %v", err)
	}
	for _, e := range boundary.es {
		if bytes.Contains(wire, []byte(e.Src)) || bytes.Contains(wire, []byte(e.H)) {
			t.Errorf("the sent list %s names a source or hash of %+v", wire, e)
		}
	}
	for _, e := range sent {
		if e.Src != "boundary:payment" || e.HasCID {
			t.Errorf("sent %+v, want src boundary:payment and no cid", e)
		}
	}
	// Each h is the commitment to its group's originals under the group's salt.
	salt, err := influence.Salt(boundary.key, boundary.rid, boundary.rcv, influence.Private, "alice")
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	h := commitTo(t, salt, boundary.es[:2])
	if !slices.ContainsFunc(sent, func(e influence.Entry) bool { return e.Owner == "alice" && e.H == h }) {
		t.Errorf("no entry sent for alice's group has the h %s", h)
	}
	// The owner-aware rule reaches the same verdict on the sent list as on the originals.
	for _, destination := range []string{"", "alice", "bob"} {
		if got, want := influence.PublicWriteRefused(sent, destination),
			influence.PublicWriteRefused(boundary.es, destination); got != want {
			t.Errorf("for %q the rule says %v on the sent list and %v on the originals", destination, got, want)
		}
	}
	// The same content in another request is sent under another h.
	again := reduce(t, boundary.es, "rid-2")
	for i := range sent {
		if sent[i].H == again[i].H {
			t.Errorf("group %d has one h in two requests", i)
		}
	}
	if got := reduce(t, nil, boundary.rid); len(got) != 0 {
		t.Errorf("no influence sent %+v", got)
	}
}

// TestReduceOwnerGroups sends an entry with an owner and the same entry without one as two groups.
func TestReduceOwnerGroups(t *testing.T) {
	e := influence.Entry{Class: influence.Private, Src: "s", H: "h"}
	owned := e
	owned.Owner = "alice"
	sent := reduce(t, []influence.Entry{e, owned}, boundary.rid)
	if len(sent) != 2 || sent[0].Owner == sent[1].Owner {
		t.Fatalf("Reduce sent %+v, want one entry with alice's owner and one with none", sent)
	}
}

func TestReduceRefuses(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, influence.KeyLength-1), make([]byte, influence.KeyLength+1)} {
		if _, err := influence.Reduce(boundary.es, key, boundary.rid, boundary.rcv, boundary.egr); err == nil {
			t.Errorf("Reduce took a %d-byte key", len(key))
		}
		if _, err := influence.Salt(key, boundary.rid, boundary.rcv, influence.Private, ""); err == nil {
			t.Errorf("Salt took a %d-byte key", len(key))
		}
	}
	if _, err := influence.Reduce(nil, boundary.key[1:], boundary.rid, boundary.rcv, boundary.egr); err == nil {
		t.Error("Reduce took a short key with no influence to reduce")
	}
	for _, egress := range []string{"", notUTF8, nonCharacter} {
		if _, err := influence.Reduce(boundary.es, boundary.key, boundary.rid, boundary.rcv, egress); err == nil {
			t.Errorf("Reduce took the egress %+q", egress)
		}
	}
	for _, es := range [][]influence.Entry{
		{{Class: "secret", Src: "s", H: "h"}},
		{{Class: influence.Public, Src: "s", H: surrogate}},
		{{Class: influence.Private, Src: "s", H: "h", Owner: notUTF8}},
	} {
		if _, err := influence.Reduce(es, boundary.key, boundary.rid, boundary.rcv, boundary.egr); err == nil {
			t.Errorf("Reduce took %+v", es)
		}
	}
	for _, rid := range []string{notUTF8, nonCharacter} {
		if _, err := influence.Salt(boundary.key, rid, boundary.rcv, influence.Private, ""); err == nil {
			t.Errorf("Salt took the rid %+q", rid)
		}
	}
	if _, err := influence.Salt(boundary.key, boundary.rid, boundary.rcv, "secret", ""); err == nil {
		t.Error("Salt took an unknown class")
	}
}

func TestSalt(t *testing.T) {
	salt := func(rid, rcv string, c influence.Class, owner string) string {
		t.Helper()
		s, err := influence.Salt(boundary.key, rid, rcv, c, owner)
		if err != nil {
			t.Fatalf("Salt: %v", err)
		}
		if len(s) != influence.SaltLength {
			t.Fatalf("the salt is %d bytes", len(s))
		}
		return b64.Encode(s)
	}
	base := salt("rid-1", "psp", influence.Private, "alice")
	for name, other := range map[string]string{
		"another rid":     salt("rid-2", "psp", influence.Private, "alice"),
		"another partner": salt("rid-1", "bank", influence.Private, "alice"),
		"another class":   salt("rid-1", "psp", influence.Public, "alice"),
		"another owner":   salt("rid-1", "psp", influence.Private, "bob"),
		"no owner":        salt("rid-1", "psp", influence.Private, ""),
	} {
		if other == base {
			t.Errorf("%s gives the same salt", name)
		}
	}
	other, _ := influence.Salt(bytes.Repeat([]byte{8}, influence.KeyLength), "rid-1", "psp", influence.Private, "alice")
	if b64.Encode(other) == base {
		t.Error("another key gives the same salt")
	}
}

// opening returns the opening of the sent entry for alice's group in the boundary's reduction.
func opening(t *testing.T) (influence.Entry, influence.Opening) {
	t.Helper()
	salt, err := influence.Salt(boundary.key, boundary.rid, boundary.rcv, influence.Private, "alice")
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	for _, sent := range reduce(t, boundary.es, boundary.rid) {
		if sent.Owner == "alice" {
			return sent, influence.Opening{
				Class: influence.Private, Owner: "alice", Salt: salt,
				Originals: []influence.Entry{boundary.es[1], boundary.es[0]},
			}
		}
	}
	t.Fatal("no entry was sent for alice's group")
	return influence.Entry{}, influence.Opening{}
}

func TestOpens(t *testing.T) {
	sent, genuine := opening(t)
	if !influence.Opens(sent, genuine) {
		t.Fatal("the genuine opening does not open")
	}
	repeated := genuine
	repeated.Originals = append(slices.Clone(genuine.Originals), genuine.Originals[0])
	if !influence.Opens(sent, repeated) {
		t.Error("an original given twice does not open, though the commitment is to the normalised group")
	}

	for name, change := range map[string]func(o *influence.Opening, sent *influence.Entry){
		"no originals":       func(o *influence.Opening, _ *influence.Entry) { o.Originals = nil },
		"a missing original": func(o *influence.Opening, _ *influence.Entry) { o.Originals = o.Originals[:1] },
		"an extra original": func(o *influence.Opening, _ *influence.Entry) {
			o.Originals = append(o.Originals, influence.Entry{Class: influence.Private, Src: "x", H: "y", Owner: "alice"})
		},
		"an altered original": func(o *influence.Opening, _ *influence.Entry) { o.Originals[0].H += "x" },
		"another class":       func(o *influence.Opening, _ *influence.Entry) { o.Class = influence.Public },
		"another owner":       func(o *influence.Opening, _ *influence.Entry) { o.Owner = "bob" },
		"no owner":            func(o *influence.Opening, _ *influence.Entry) { o.Owner = "" },
		"an original's other owner": func(o *influence.Opening, _ *influence.Entry) {
			o.Originals = append(o.Originals, influence.Entry{Class: influence.Private, Src: "s", H: "h", Owner: "bob"})
		},
		"an original's other class": func(o *influence.Opening, _ *influence.Entry) {
			o.Originals = append(o.Originals, influence.Entry{Class: influence.Public, Src: "s", H: "h", Owner: "alice"})
		},
		"a short salt":  func(o *influence.Opening, _ *influence.Entry) { o.Salt = o.Salt[:influence.SaltLength-1] },
		"a long salt":   func(o *influence.Opening, _ *influence.Entry) { o.Salt = append(o.Salt, 0) },
		"another salt":  func(o *influence.Opening, _ *influence.Entry) { o.Salt[0] ^= 1 },
		"another h":     func(_ *influence.Opening, sent *influence.Entry) { sent.H += "x" },
		"a sent class":  func(_ *influence.Opening, sent *influence.Entry) { sent.Class = influence.Public },
		"a sent owner":  func(_ *influence.Opening, sent *influence.Entry) { sent.Owner = "" },
		"invalid text":  func(o *influence.Opening, _ *influence.Entry) { o.Originals[0].Src = notUTF8 },
		"unknown class": func(o *influence.Opening, sent *influence.Entry) { o.Class, sent.Class = "secret", "secret" },
	} {
		t.Run(name, func(t *testing.T) {
			s, o := opening(t)
			change(&o, &s)
			if influence.Opens(s, o) {
				t.Fatal("it opens")
			}
		})
	}
	if influence.Opens(influence.Entry{}, influence.Opening{}) {
		t.Error("the zero opening opens the zero entry")
	}
}

// TestOpensChecksBeforeTheCommitment refuses an opening whose commitment is the sent entry's h but that
// breaks another condition: one Reduce never sends, made here by computing the commitment directly.
func TestOpensChecksBeforeTheCommitment(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, influence.SaltLength)
	alice := influence.Entry{Class: influence.Private, Src: "s", H: "h", Owner: "alice"}
	for _, c := range []struct {
		name      string
		salt      []byte
		originals []influence.Entry
		opens     bool
	}{
		{"a genuine opening", salt, []influence.Entry{alice}, true},
		{"no originals", salt, nil, false},
		{"an original of another owner", salt,
			[]influence.Entry{alice, {Class: influence.Private, Src: "s", H: "g", Owner: "bob"}}, false},
		{"an original with no owner", salt, []influence.Entry{alice, {Class: influence.Private, Src: "s", H: "g"}}, false},
		{"an original of another class", salt,
			[]influence.Entry{alice, {Class: influence.Public, Src: "s", H: "g", Owner: "alice"}}, false},
		{"a short salt", salt[:influence.SaltLength-1], []influence.Entry{alice}, false},
		{"a long salt", append(slices.Clone(salt), 0), []influence.Entry{alice}, false},
	} {
		sent := influence.Entry{
			Class: influence.Private, Src: "boundary:payment", H: commitTo(t, c.salt, c.originals), Owner: "alice",
		}
		o := influence.Opening{Class: influence.Private, Owner: "alice", Salt: c.salt, Originals: c.originals}
		if got := influence.Opens(sent, o); got != c.opens {
			t.Errorf("%s: Opens = %v, want %v", c.name, got, c.opens)
		}
	}
}

// commitTo returns the commitment to originals under salt, computed here by the spec's formula,
// b64url(SHA-256("paztport-boundary-entry\n" || salt || JCS(normalise(originals)))), with no check of
// the salt or the originals.
func commitTo(t *testing.T, salt []byte, originals []influence.Entry) string {
	t.Helper()
	body, err := influence.EntriesWire(influence.Normalise(originals))
	if err != nil {
		t.Fatalf("EntriesWire: %v", err)
	}
	msg := append([]byte("paztport-boundary-entry\n"), salt...)
	sum := sha256.Sum256(append(msg, body...))
	return b64.Encode(sum[:])
}

// TestOpeningWire writes an opening as its wire bytes and reads it back, with and without an owner.
func TestOpeningWire(t *testing.T) {
	_, o := opening(t)
	unowned := influence.Opening{Class: influence.ThirdParty, Salt: o.Salt, Originals: []influence.Entry{boundary.es[2]}}
	for _, o := range []influence.Opening{o, unowned} {
		wire, err := o.Wire()
		if err != nil {
			t.Fatalf("Wire: %v", err)
		}
		back, err := influence.ParseOpening(wire)
		if err != nil {
			t.Fatalf("ParseOpening: %v", err)
		}
		if back.Class != o.Class || back.Owner != o.Owner || !bytes.Equal(back.Salt, o.Salt) ||
			!slices.Equal(back.Originals, o.Originals) {
			t.Fatalf("read back %+v, want %+v", back, o)
		}
	}
	for name, change := range map[string]func(o *influence.Opening){
		"an unknown class":    func(o *influence.Opening) { o.Class = "secret" },
		"a short salt":        func(o *influence.Opening) { o.Salt = o.Salt[:1] },
		"an unknown original": func(o *influence.Opening) { o.Originals = []influence.Entry{{Class: "secret"}} },
		"invalid text":        func(o *influence.Opening) { o.Owner = notUTF8 },
	} {
		_, o := opening(t)
		change(&o)
		if b, err := o.Wire(); err == nil {
			t.Errorf("%s: Wire wrote %s", name, b)
		}
	}
}

// TestParseOpeningRefuses refuses bytes that are not an opening, telling those that are not one object in
// wire bytes from an object that is not an opening.
func TestParseOpeningRefuses(t *testing.T) {
	const salt = `"-kN8YOjmxnwiGm4BTq9hXw"`
	const original = `{"cls":"private","h":"h","owner":"alice","src":"s"}`
	for _, c := range []struct {
		name, wire string
		notObject  bool
	}{
		{"whitespace", `{"cls":"private", "originals":[],"salt":` + salt + `}`, true},
		{"members out of order", `{"salt":` + salt + `,"cls":"private","originals":[]}`, true},
		{"an array", `[]`, true},
		{"a string", `"secret"`, true},
		{"no bytes", ``, true},
		{"no salt", `{"cls":"private","originals":[]}`, false},
		{"another member", `{"cls":"private","originals":[],"salt":` + salt + `,"secret":1}`, false},
		{"an unknown class", `{"cls":"secret","originals":[],"salt":` + salt + `}`, false},
		{"an empty owner", `{"cls":"private","originals":[],"owner":"","salt":` + salt + `}`, false},
		{"a short salt", `{"cls":"private","originals":[],"salt":"AAAA"}`, false},
		{"a salt with padding", `{"cls":"private","originals":[],"salt":"-kN8YOjmxnwiGm4BTq9hXw=="}`, false},
		{"a salt that is not a string", `{"cls":"private","originals":[],"salt":16}`, false},
		{"originals not an array", `{"cls":"private","originals":` + original + `,"salt":` + salt + `}`, false},
		{"a malformed original",
			`{"cls":"private","originals":[` + original + `,{"cls":"private"}],"salt":` + salt + `}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := influence.ParseOpening([]byte(c.wire))
			if err == nil {
				t.Fatal("ParseOpening read it")
			}
			if got := errors.Is(err, influence.ErrNotObject); got != c.notObject {
				t.Fatalf("errors.Is(%q, ErrNotObject) = %v", err, got)
			}
			if !strings.HasPrefix(err.Error(), "paztport influence: malformed opening: ") ||
				strings.Contains(err.Error(), "secret") {
				t.Fatalf("the refusal %q is not the opening's, or quotes the input", err)
			}
		})
	}
	if o, err := influence.ParseOpening([]byte(`{"cls":"private","originals":[],"salt":` + salt + `}`)); err != nil ||
		len(o.Originals) != 0 {
		t.Fatalf("ParseOpening of an opening with no originals = %+v, %v; it reads, and opens nothing", o, err)
	}
}
