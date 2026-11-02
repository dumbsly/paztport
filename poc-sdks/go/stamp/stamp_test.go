// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// bs is a backslash, so that JSON escapes in this file are built from parts and never typed whole.
const bs = `\`

// surrogate is the Go string that stands for a lone surrogate: U+D800's three-byte pattern, which is not
// valid UTF-8.
const surrogate = "\xed\xa0\x80"

var (
	key     = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub     = key.Public().(ed25519.PublicKey)
	unsaved = stamp.Stamp{Svc: "pi", Inst: "pi-1", RID: "rid-1", TS: 1000, Sess: "s", Rcv: "next", Bind: "b"}

	// signedFields are the names of the string fields a stamp's signature covers.
	signedFields = []string{"svc", "inst", "rid", "sess", "rcv", "bind", "infl", "prev"}
)

// signed returns unsaved, signed with key.
func signed(t *testing.T) stamp.Stamp {
	t.Helper()
	s, err := stamp.Sign(unsaved, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return s
}

// members returns the members of the signed stamp, to change before writing a chain of them.
func members(t *testing.T) []json.Member {
	t.Helper()
	b, err := stamp.Chain{signed(t)}.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	v, err := json.ReadWire(b)
	if err != nil {
		t.Fatalf("ReadWire: %v", err)
	}
	return v.Items()[0].Members()
}

// with returns ms with the member called name set to v, added if ms has none.
func with(ms []json.Member, name string, v json.Value) []json.Member {
	out := without(ms, name)
	return append(out, json.Member{Name: name, Value: v})
}

// without returns ms less the member called name.
func without(ms []json.Member, name string) []json.Member {
	return slices.DeleteFunc(slices.Clone(ms), func(m json.Member) bool { return m.Name == name })
}

// chain returns the wire bytes of a chain of stamps holding these members, so that each is refused for
// what it holds, not for how its bytes are written.
func chain(t *testing.T, stamps ...[]json.Member) []byte {
	t.Helper()
	items := make([]json.Value, len(stamps))
	for i, ms := range stamps {
		items[i] = json.Obj(ms...)
	}
	b, err := json.Wire(json.Arr(items...))
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
}

// chainWith returns the wire bytes of a one-stamp chain whose member name has the text value, written
// exactly as given, in the place a canonical writer puts it.
func chainWith(t *testing.T, name, value string) []byte {
	t.Helper()
	b := chain(t, with(members(t), name, json.S("@")))
	marked := []byte(`"` + name + `":"@"`)
	if bytes.Count(b, marked) != 1 {
		t.Fatalf("the member %s is not in the chain once", name)
	}
	return bytes.Replace(b, marked, []byte(`"`+name+`":`+value), 1)
}

// reads checks that ParseChain answers want for b, and that ReadChain answers the same for its token.
func reads(t *testing.T, want reason.Code, b []byte) {
	t.Helper()
	c, got := stamp.ParseChain(b)
	if got != want {
		t.Errorf("ParseChain = %s, want %s, for %q", got, want, b)
	}
	if got != reason.OK && c != nil {
		t.Errorf("ParseChain refused %q as %s but returned stamps", b, got)
	}
	if _, got := stamp.ReadChain(b64.Encode(b)); got != want {
		t.Errorf("ReadChain = %s, want %s, for the token of %q", got, want, b)
	}
}

func TestChainRoundTrip(t *testing.T) {
	first := signed(t)
	next := first
	next.Svc, next.Rcv, next.Prev = "next", "last", first.Sig
	next, err := stamp.Sign(next, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	want := stamp.Chain{first, next}
	b, err := want.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	got, code := stamp.ParseChain(b)
	if code != reason.OK || !slices.Equal(got, want) {
		t.Fatalf("ParseChain = %v, %s, want the chain written", got, code)
	}
	tok, err := want.Token()
	if err != nil || tok != b64.Encode(b) {
		t.Fatalf("Token = %q, %v, want the base64url of the wire bytes", tok, err)
	}
	if got, code := stamp.ReadChain(tok); code != reason.OK || !slices.Equal(got, want) {
		t.Fatalf("ReadChain = %v, %s, want the chain written", got, code)
	}
	one, err := first.Wire()
	if err != nil {
		t.Fatalf("Stamp.Wire: %v", err)
	}
	if !bytes.Equal(b[:len(one)+1], append([]byte("["), one...)) {
		t.Fatalf("a chain's first item is not its first stamp's wire bytes: %s", b)
	}
}

func TestChainWireIsCanonical(t *testing.T) {
	b, err := stamp.Chain{signed(t)}.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	s := signed(t)
	want := `[{"bind":"b","infl":"","inst":"pi-1","prev":"","rcv":"next","rid":"rid-1","sess":"s","sig":"` + s.Sig +
		`","svc":"pi","ts":1000,"v":3}]`
	if string(b) != want {
		t.Fatalf("Wire = %s, want %s", b, want)
	}
}

func TestNotAChain(t *testing.T) {
	one, err := signed(t).Wire()
	if err != nil {
		t.Fatalf("Stamp.Wire: %v", err)
	}
	canonical := chain(t, members(t))
	// The members in the order the spec lists them, not in JCS order.
	listed := `[{"v":3,"svc":"pi","inst":"pi-1","rid":"rid-1","ts":1000,"sess":"s","rcv":"next","bind":"b",` +
		`"infl":"","prev":"","sig":"` + signed(t).Sig + `"}]`
	for name, b := range map[string][]byte{
		"no bytes":            nil,
		"not JSON":            []byte("chain"),
		"a stamp":             one,
		"a string":            []byte(`"x"`),
		"an empty array":      []byte("[]"),
		"an array of a 7":     []byte("[7]"),
		"an array of null":    []byte("[null]"),
		"an array of a chain": append(append([]byte("["), canonical...), ']'),
		"whitespace":          append(append([]byte("[ "), one...), " ]"...),
		"listed member order": []byte(listed),
	} {
		t.Run(name, func(t *testing.T) { reads(t, reason.ChainMissing, b) })
	}
	for name, tok := range map[string]string{
		"empty": "", "not base64url": "!!", "padded": b64.Encode(canonical) + "=",
	} {
		t.Run("token "+name, func(t *testing.T) {
			if _, got := stamp.ReadChain(tok); got != reason.ChainMissing {
				t.Fatalf("ReadChain = %s, want %s", got, reason.ChainMissing)
			}
		})
	}
	reads(t, reason.OK, canonical)
}

func TestEveryMemberIsRequired(t *testing.T) {
	for _, m := range members(t) {
		t.Run(m.Name, func(t *testing.T) { reads(t, reason.ChainMissing, chain(t, without(members(t), m.Name))) })
	}
}

func TestNoOtherMember(t *testing.T) {
	reads(t, reason.ChainMissing, chain(t, with(members(t), "extra", json.B(true))))
	reads(t, reason.ChainMissing, chain(t, with(members(t), "V", json.I(3))))
}

func TestVersionIsThree(t *testing.T) {
	for name, v := range map[string]json.Value{
		"1": json.I(1), "2": json.I(2), "4": json.I(4), "0": json.I(0), "text": json.S("3"), "null": json.Null(),
	} {
		t.Run(name, func(t *testing.T) {
			odd := with(members(t), "v", v)
			reads(t, reason.ChainMissing, chain(t, odd))
			reads(t, reason.ChainMissing, chain(t, odd, members(t)))
			reads(t, reason.ChainMissing, chain(t, members(t), odd))
		})
	}
}

func TestTSIsAProtocolInteger(t *testing.T) {
	for _, text := range []string{
		"1.5", "1.0", "1000.0", "1e3", "-1", "-0", "9007199254740992", "-9007199254740991", `"1"`, "null",
		"1e400", "-9223372036854775808", "9223372036854775807", "01",
	} {
		t.Run(text, func(t *testing.T) { reads(t, reason.ChainMissing, chainWith(t, "ts", text)) })
	}
	for _, ts := range []int64{0, json.MaxSafe} {
		c, code := stamp.ParseChain(chain(t, with(members(t), "ts", json.I(ts))))
		if code != reason.OK || c[0].TS != ts {
			t.Errorf("ParseChain of ts %d = %v, %s", ts, c, code)
		}
	}
}

func TestStringFields(t *testing.T) {
	for _, name := range append(slices.Clone(signedFields), "sig") {
		t.Run(name, func(t *testing.T) {
			for what, v := range map[string]json.Value{
				"an integer": json.I(7), "null": json.Null(), "a boolean": json.B(false),
				"an array": json.Arr(), "an object": json.Obj(),
			} {
				t.Run(what, func(t *testing.T) { reads(t, reason.ChainMissing, chain(t, with(members(t), name, v))) })
			}
			for what, text := range map[string]string{
				"an escaped lone surrogate": `"a` + bs + `ud800"`,
				"a lone surrogate's bytes":  `"a` + surrogate + `"`,
				"a noncharacter":            `"a` + string(rune(0xFDD0)) + `"`,
				"the last noncharacter":     `"a` + string(rune(0x10FFFF)) + `"`,
			} {
				t.Run(what, func(t *testing.T) { reads(t, reason.ChainMissing, chainWith(t, name, text)) })
			}
		})
	}
}

func TestSigIsCanonicalBase64url(t *testing.T) {
	sig := signed(t).Sig
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, sig[len(sig)-1])
	// A 64-byte sig ends in a character two of whose bits are past the last byte; flipping the lowest
	// leaves a text that decodes only by ignoring them.
	trailing := sig[:len(sig)-1] + string(alphabet[last^1])
	if _, err := b64.Decode(trailing); err == nil {
		t.Fatal("the tweaked sig decodes, so it can't test the reader")
	}
	for name, s := range map[string]string{
		"padded":                 sig + "==",
		"a length no bytes have": sig[:len(sig)-1], // 85 characters, one more than a multiple of 4
		"trailing bits":          trailing,
		"standard base64":        strings.Repeat("+/", 43),
		"not the alphabet":       "!!!",
		"a space":                sig[:4] + " " + sig[5:],
	} {
		t.Run(name, func(t *testing.T) { reads(t, reason.ChainMissing, chain(t, with(members(t), "sig", json.S(s)))) })
	}
	// The reader pins the encoding, not the length: a sig of another length reads, and fails as a
	// signature, which the verifier's signature check reports.
	for name, n := range map[string]int{"empty": 0, "63 bytes": 63, "65 bytes": 65} {
		t.Run(name, func(t *testing.T) {
			s := b64.Encode(make([]byte, n))
			c, code := stamp.ParseChain(chain(t, with(members(t), "sig", json.S(s))))
			if code != reason.OK || c[0].Sig != s {
				t.Fatalf("ParseChain = %v, %s, want the stamp read", c, code)
			}
		})
	}
}

func TestDelimiterIsABadSignature(t *testing.T) {
	for _, name := range signedFields {
		t.Run(name, func(t *testing.T) {
			bar := with(members(t), name, json.S("a|b"))
			reads(t, reason.BadSignature, chain(t, bar))
			reads(t, reason.BadSignature, chain(t, members(t), bar))
		})
	}
}

// TestStructuralFaultOutranksDelimiter checks that every stamp is read before any is checked for the
// delimiter, so a chain with both faults is CHAIN_MISSING, wherever each fault is.
func TestStructuralFaultOutranksDelimiter(t *testing.T) {
	bar := with(members(t), "inst", json.S("a|b"))
	for name, broken := range map[string][]json.Member{
		"a member missing": without(members(t), "rcv"),
		"ts as text":       with(members(t), "ts", json.S("1")),
	} {
		t.Run(name, func(t *testing.T) {
			reads(t, reason.ChainMissing, chain(t, broken, bar))
			reads(t, reason.ChainMissing, chain(t, bar, broken))
		})
	}
}

func TestChainWireRefuses(t *testing.T) {
	s := signed(t)
	edit := func(f func(*stamp.Stamp)) stamp.Chain {
		c := s
		f(&c)
		return stamp.Chain{s, c}
	}
	for name, c := range map[string]stamp.Chain{
		"no stamps":            nil,
		"a delimiter":          edit(func(s *stamp.Stamp) { s.Rcv = "a|b" }),
		"a lone surrogate":     edit(func(s *stamp.Stamp) { s.Bind = surrogate }),
		"a noncharacter":       edit(func(s *stamp.Stamp) { s.Infl = string(rune(0xFFFE)) }),
		"a negative ts":        edit(func(s *stamp.Stamp) { s.TS = -1 }),
		"ts past 2^53 - 1":     edit(func(s *stamp.Stamp) { s.TS = json.MaxSafe + 1 }),
		"sig not base64url":    edit(func(s *stamp.Stamp) { s.Sig = "a=" }),
		"sig with a surrogate": edit(func(s *stamp.Stamp) { s.Sig = surrogate }),
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := c.Wire(); err == nil {
				t.Fatalf("Wire wrote %s", b)
			}
			if tok, err := c.Token(); err == nil {
				t.Fatalf("Token wrote %s", tok)
			}
		})
	}
}

func TestSign(t *testing.T) {
	s := signed(t)
	msg, err := s.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if want := "3|pi|pi-1|rid-1|1000|s|next|b||"; string(msg) != want {
		t.Fatalf("SigningBytes = %q, want %q", msg, want)
	}
	sig, err := b64.Decode(s.Sig)
	if err != nil || !keys.Verify(pub, msg, sig) {
		t.Fatal("the sig does not verify over the signing bytes")
	}
	other := s
	other.Sig = "AAAA"
	if b, err := other.SigningBytes(); err != nil || !bytes.Equal(b, msg) {
		t.Fatal("the signing bytes depend on the sig")
	}
	again, err := stamp.Sign(other, key)
	if err != nil || again != s {
		t.Fatal("Sign kept a sig it was given")
	}
	for _, ts := range []int64{0, json.MaxSafe} {
		f := unsaved
		f.TS = ts
		if _, err := stamp.Sign(f, key); err != nil {
			t.Errorf("Sign refused ts %d: %v", ts, err)
		}
	}
}

func TestSignRefuses(t *testing.T) {
	type field struct {
		name string
		set  func(*stamp.Stamp, string)
	}
	setters := []field{
		{"svc", func(s *stamp.Stamp, v string) { s.Svc = v }},
		{"inst", func(s *stamp.Stamp, v string) { s.Inst = v }},
		{"rid", func(s *stamp.Stamp, v string) { s.RID = v }},
		{"sess", func(s *stamp.Stamp, v string) { s.Sess = v }},
		{"rcv", func(s *stamp.Stamp, v string) { s.Rcv = v }},
		{"bind", func(s *stamp.Stamp, v string) { s.Bind = v }},
		{"infl", func(s *stamp.Stamp, v string) { s.Infl = v }},
		{"prev", func(s *stamp.Stamp, v string) { s.Prev = v }},
	}
	if len(setters) != len(signedFields) {
		t.Fatal("a signed field has no setter")
	}
	for _, f := range setters {
		for what, v := range map[string]string{
			"a delimiter":      "a|b",
			"a lone surrogate": "a" + surrogate,
			"a cut-short rune": "a\xc3",
			"a noncharacter":   "a" + string(rune(0xFDEF)),
		} {
			t.Run(f.name+" with "+what, func(t *testing.T) {
				s := unsaved
				f.set(&s, v)
				refuses(t, s, key)
				if strings.Contains(refusal(t, s), v) {
					t.Error("the refusal quotes the field")
				}
			})
		}
	}
	for name, ts := range map[string]int64{"-1": -1, "2^53": json.MaxSafe + 1, "-2^63": -1 << 63} {
		t.Run("ts "+name, func(t *testing.T) {
			s := unsaved
			s.TS = ts
			refuses(t, s, key)
		})
	}
	t.Run("a short key", func(t *testing.T) {
		if _, err := stamp.Sign(unsaved, key[:63]); err == nil {
			t.Fatal("Sign signed with a 63-byte key")
		}
	})
}

// refuses checks that Sign refuses s and that s has no signing bytes.
func refuses(t *testing.T, s stamp.Stamp, k ed25519.PrivateKey) {
	t.Helper()
	if got, err := stamp.Sign(s, k); err == nil {
		t.Errorf("Sign signed it as %s", got.Sig)
	}
	if b, err := s.SigningBytes(); err == nil {
		t.Errorf("SigningBytes gave %q", b)
	}
}

// refusal returns the text of Sign's refusal of s.
func refusal(t *testing.T, s stamp.Stamp) string {
	t.Helper()
	_, err := stamp.Sign(s, key)
	if err == nil {
		t.Fatal("Sign signed it")
	}
	return err.Error()
}

func TestPromptBinding(t *testing.T) {
	got, err := stamp.PromptBinding("fix the typo")
	sum := sha256.Sum256([]byte("prompt\nfix the typo"))
	if err != nil || got != b64.Encode(sum[:]) {
		t.Fatalf("PromptBinding = %s, %v", got, err)
	}
	for _, bad := range []string{surrogate, "a\xff", "\xc3"} {
		if got, err := stamp.PromptBinding(bad); err == nil {
			t.Errorf("PromptBinding computed %s over text that is not valid UTF-8", got)
		}
	}
}

func TestResponseBinding(t *testing.T) {
	ls := []influence.Label{{Class: influence.Private, CID: "c1", Owner: "alice"}, {Class: influence.Public, CID: "c2"}}
	got, err := stamp.ResponseBinding("rh", "call-1", ls)
	sum := sha256.Sum256([]byte(`rh` + "\n" + `call-1` + "\n" +
		`[{"cid":"c1","cls":"private","owner":"alice"},{"cid":"c2","cls":"public"}]`))
	if err != nil || got != b64.Encode(sum[:]) {
		t.Fatalf("ResponseBinding = %s, %v", got, err)
	}
	none, err := stamp.ResponseBinding("rh", "call-1", nil)
	sum = sha256.Sum256([]byte("rh\ncall-1\n[]"))
	if err != nil || none != b64.Encode(sum[:]) {
		t.Fatalf("ResponseBinding with no labels = %s, %v", none, err)
	}
	for name, args := range map[string][2]string{
		"a newline in the call id":            {"rh", "call\n1"},
		"a call id ending in a newline":       {"rh", "call-1\n"},
		"a lone surrogate in the result hash": {"rh" + surrogate, "call-1"},
		"a lone surrogate in the call id":     {"rh", "call-" + surrogate},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := stamp.ResponseBinding(args[0], args[1], ls); err == nil {
				t.Fatalf("ResponseBinding computed %s", got)
			}
		})
	}
	for name, l := range map[string]influence.Label{
		"an unknown class":      {Class: "secret", CID: "c1"},
		"a cid not valid UTF-8": {Class: influence.Public, CID: surrogate},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := stamp.ResponseBinding("rh", "call-1", []influence.Label{l}); err == nil {
				t.Fatalf("ResponseBinding computed %s", got)
			}
		})
	}
}

// The stamper's tests run a mesh of gateway, the origin, then orders, then payment.

const (
	rid = "rid-7"
	now = int64(1767225600000)
)

var (
	gatewayKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	ordersKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	paymentKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	shaped     = []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h1"}}
)

// stamper returns svc's stamper, its instance svc-1, signing at now and minting rid.
func stamper(svc string, k ed25519.PrivateKey, origin bool) *stamp.Stamper {
	return &stamp.Stamper{Svc: svc, Inst: svc + "-1", Key: k, Origin: origin,
		NewRID: func() string { return rid }, Now: func() int64 { return now }}
}

// bundle returns a proof bundle holding a proof, labelled by its root id, for each route.
func bundle(routes ...string) policy.ProofBundle {
	b := policy.ProofBundle{Proofs: map[string]policy.Proof{}}
	for _, r := range routes {
		b.Proofs[r] = policy.Proof{RootID: "for " + r}
	}
	return b
}

// verifies checks that s's sig verifies under k's public half.
func verifies(t *testing.T, s stamp.Stamp, k ed25519.PrivateKey) {
	t.Helper()
	msg, err := s.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	sig, err := b64.Decode(s.Sig)
	if err != nil || !keys.Verify(k.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("the stamp's sig does not verify")
	}
}

// proofFor checks that p is the bundle's proof for route, or nil when route is "".
func proofFor(t *testing.T, p *policy.Proof, route string) {
	t.Helper()
	switch {
	case route == "" && p != nil:
		t.Fatalf("got the proof %s, want none", p.RootID)
	case route != "" && (p == nil || p.RootID != "for "+route):
		t.Fatalf("got the proof %v, want the one for %s", p, route)
	}
}

func TestNextAtTheOrigin(t *testing.T) {
	commit, err := influence.Commit(shaped)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	ignored := stamp.Chain{signed(t)}
	c, p, err := stamper("gateway", gatewayKey, true).Next(ignored, "orders", "b1", shaped, bundle("gateway/orders"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("the origin's chain has %d stamps, want 1", len(c))
	}
	want := stamp.Stamp{Svc: "gateway", Inst: "gateway-1", RID: rid, TS: now, Sess: "", Rcv: "orders", Bind: "b1",
		Infl: commit, Prev: "", Sig: c[0].Sig}
	if c[0] != want {
		t.Fatalf("the origin stamp is %+v, want %+v", c[0], want)
	}
	verifies(t, c[0], gatewayKey)
	proofFor(t, p, "gateway/orders")
}

// TestNextAppends appends to a two-stamp chain whose stamps differ in rid and sess, as no verified chain
// does, to show where each comes from: the rid is the origin's, and the sess the last stamp's.
func TestNextAppends(t *testing.T) {
	origin, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", nil, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	hop := stamp.Stamp{Svc: "orders", Inst: "orders-1", RID: "rid-other", TS: now, Sess: "sess-1", Rcv: "payment",
		Bind: "b2", Prev: origin[0].Sig}
	if hop, err = stamp.Sign(hop, ordersKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	inbound := stamp.Chain{origin[0], hop}
	roomy := append(make(stamp.Chain, 0, 4), inbound...)
	kept := slices.Clone(roomy[:cap(roomy)])

	payment := stamper("payment", paymentKey, false)
	c, p, err := payment.Next(roomy, "bank", "b3", nil, bundle("gateway/orders/payment/bank"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(c) != 3 || !slices.Equal(c[:2], inbound) {
		t.Fatalf("the chain is %+v, want the inbound stamps then one more", c)
	}
	want := stamp.Stamp{Svc: "payment", Inst: "payment-1", RID: rid, TS: now, Sess: "sess-1", Rcv: "bank", Bind: "b3",
		Infl: "", Prev: hop.Sig, Sig: c[2].Sig}
	if c[2] != want {
		t.Fatalf("the appended stamp is %+v, want %+v", c[2], want)
	}
	verifies(t, c[2], paymentKey)
	proofFor(t, p, "gateway/orders/payment/bank")
	if !slices.Equal(roomy[:cap(roomy)], kept) {
		t.Fatal("Next wrote into the inbound chain's spare capacity")
	}

	_, p, err = payment.Next(inbound, "search", "b3", nil, bundle("gateway/orders/payment/bank"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	proofFor(t, p, "")
}

func TestNextRefuses(t *testing.T) {
	orders := stamper("orders", ordersKey, false)
	inbound := stamp.Chain{signed(t)}
	for name, f := range map[string]func() error{
		"no inbound chain": func() error { _, _, err := orders.Next(nil, "payment", "b", nil, bundle()); return err },
		"an empty inbound chain": func() error {
			_, _, err := orders.Next(stamp.Chain{}, "payment", "b", nil, bundle())
			return err
		},
		"a delimiter in the receiver": func() error {
			_, _, err := orders.Next(inbound, "pay|ment", "b", nil, bundle())
			return err
		},
		"influence that can't be committed": func() error {
			_, _, err := orders.Next(inbound, "payment", "b", []influence.Entry{{Class: "secret"}}, bundle())
			return err
		},
		"no clock": func() error {
			s := *orders
			s.Now = nil
			_, _, err := s.Next(inbound, "payment", "b", nil, bundle())
			return err
		},
		"an origin with no rid": func() error {
			s := *stamper("gateway", gatewayKey, true)
			s.NewRID = nil
			_, _, err := s.Next(nil, "orders", "b", nil, bundle())
			return err
		},
		"a clock past 2^53 - 1": func() error {
			s := *orders
			s.Now = func() int64 { return json.MaxSafe + 1 }
			_, _, err := s.Next(inbound, "payment", "b", nil, bundle())
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if f() == nil {
				t.Fatal("Next stamped it")
			}
		})
	}
}

func TestBoundary(t *testing.T) {
	commit, err := influence.Commit(shaped)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	internal, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", nil, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	orders := stamper("orders", ordersKey, false)
	c, p, err := orders.Boundary(internal, "sess-1", "psp", "b3", shaped, bundle("orders/psp", "gateway/orders/psp"))
	if err != nil {
		t.Fatalf("Boundary: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("the boundary chain has %d stamps, want 1", len(c))
	}
	want := stamp.Stamp{Svc: "orders", Inst: "orders-1", RID: rid, TS: now, Sess: "sess-1", Rcv: "psp", Bind: "b3",
		Infl: commit, Prev: "", Sig: c[0].Sig}
	if c[0] != want {
		t.Fatalf("the boundary stamp is %+v, want %+v", c[0], want)
	}
	verifies(t, c[0], ordersKey)
	proofFor(t, p, "orders/psp")

	if _, p, err = orders.Boundary(internal, "sess-1", "psp", "b3", nil, bundle("gateway/orders/psp")); err != nil {
		t.Fatalf("Boundary: %v", err)
	}
	proofFor(t, p, "")

	if _, _, err := orders.Boundary(internal, "", "psp", "b3", nil, bundle()); err == nil {
		t.Error("Boundary stamped a call in no session, which would be a valid in-mesh origin stamp")
	}
	for _, none := range []stamp.Chain{nil, {}} {
		if _, _, err := orders.Boundary(none, "sess-1", "psp", "b3", nil, bundle()); err == nil {
			t.Error("Boundary stamped a call with no internal chain")
		}
	}
}

func TestRespond(t *testing.T) {
	gateway := stamper("gateway", gatewayKey, true)
	request, _, err := gateway.Next(nil, "orders", "b1", nil, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	ls := []influence.Label{{Class: influence.Private, CID: "c1", Owner: "alice"}}
	orders := stamper("orders", ordersKey, false)
	orders.Now = func() int64 { return now + 5 }
	s, err := orders.Respond(request, "rh", rid, ls)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	bind, err := stamp.ResponseBinding("rh", rid, ls)
	if err != nil {
		t.Fatalf("ResponseBinding: %v", err)
	}
	want := stamp.Stamp{Svc: "orders", Inst: "orders-1", RID: rid, TS: now + 5, Sess: request[0].Sess,
		Rcv: "gateway", Bind: bind, Infl: "", Prev: request[0].Sig, Sig: s.Sig}
	if s != want {
		t.Fatalf("the response stamp is %+v, want %+v", s, want)
	}
	verifies(t, s, ordersKey)

	for _, none := range []stamp.Chain{nil, {}} {
		if _, err := orders.Respond(none, "rh", rid, nil); err == nil {
			t.Error("Respond stamped a response to no request")
		}
	}
	if _, err := orders.Respond(request, "rh", "call\n1", nil); err == nil {
		t.Error("Respond stamped a response whose binding can't be computed")
	}
}

// TestAnOriginNeverResponds checks the rule that keeps a response stamp from minting origin stamps. A
// response is shaped like a request stamp, so an origin's response to a forged one-stamp chain with an
// empty sig has prev "" and would be a valid origin stamp, addressed to whichever service the forgery
// named.
func TestAnOriginNeverResponds(t *testing.T) {
	forged := stamp.Chain{{Svc: "orders", Inst: "x", RID: rid, TS: now, Rcv: "gateway", Bind: "b"}}
	if s, err := stamper("gateway", gatewayKey, true).Respond(forged, "h", rid, nil); err == nil {
		t.Fatalf("the origin responded with %+v", s)
	}
}
