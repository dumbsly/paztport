// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

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
	signedFields = []string{"svc", "inst", "rid", "sess", "rcv", "bind", "ext", "prev"}
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
	want := `[{"bind":"b","ext":"","inst":"pi-1","prev":"","rcv":"next","rid":"rid-1","sess":"s","sig":"` + s.Sig +
		`","svc":"pi","ts":1000,"v":4}]`
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
	listed := `[{"v":4,"svc":"pi","inst":"pi-1","rid":"rid-1","ts":1000,"sess":"s","rcv":"next","bind":"b",` +
		`"ext":"","prev":"","sig":"` + signed(t).Sig + `"}]`
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
	reads(t, reason.ChainMissing, chain(t, with(members(t), "V", json.I(stamp.Version))))
}

// TestVersionIsFour reads only a stamp whose v is 4: version 3's stamps, whose signed bytes and members differ,
// do not read, so a version 3 chain is CHAIN_MISSING wherever its stamp is.
func TestVersionIsFour(t *testing.T) {
	if stamp.Version != 4 {
		t.Fatalf("Version = %d, want 4", stamp.Version)
	}
	for name, v := range map[string]json.Value{
		"1": json.I(1), "3": json.I(3), "5": json.I(5), "0": json.I(0), "text": json.S("4"), "null": json.Null(),
	} {
		t.Run(name, func(t *testing.T) {
			odd := with(members(t), "v", v)
			reads(t, reason.ChainMissing, chain(t, odd))
			reads(t, reason.ChainMissing, chain(t, odd, members(t)))
			reads(t, reason.ChainMissing, chain(t, members(t), odd))
		})
	}
}

// TestVersionThreesMemberDoesNotRead: version 3's infl in place of ext, or beside it, is a member a stamp does
// not have, so neither reads.
func TestVersionThreesMemberDoesNotRead(t *testing.T) {
	ext := members(t)
	infl := with(without(ext, "ext"), "infl", json.S(""))
	both := with(ext, "infl", json.S(""))
	for name, ms := range map[string][]json.Member{"infl in place of ext": infl, "infl beside ext": both} {
		t.Run(name, func(t *testing.T) {
			reads(t, reason.ChainMissing, chain(t, ms))
			reads(t, reason.ChainMissing, chain(t, members(t), ms))
		})
	}
}

// TestAFieldHoldingThePipeReads: the signed bytes are JCS, so no field needs a rule against "|", and a stamp
// with one in each string field reads as itself.
func TestAFieldHoldingThePipeReads(t *testing.T) {
	for _, name := range signedFields {
		t.Run(name, func(t *testing.T) {
			bar := with(members(t), name, json.S("a|b"))
			reads(t, reason.OK, chain(t, bar))
			reads(t, reason.OK, chain(t, members(t), bar))
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

// TestWireRefuses writes a stamp no reader would read, alone and in a chain: each writer refuses it.
func TestWireRefuses(t *testing.T) {
	s := signed(t)
	edit := func(f func(*stamp.Stamp)) stamp.Stamp {
		c := s
		f(&c)
		return c
	}
	for name, bad := range map[string]stamp.Stamp{
		"a lone surrogate":       edit(func(s *stamp.Stamp) { s.Bind = surrogate }),
		"a noncharacter":         edit(func(s *stamp.Stamp) { s.Ext = string(rune(0xFFFE)) }),
		"a negative ts":          edit(func(s *stamp.Stamp) { s.TS = -1 }),
		"ts past 2^53 - 1":       edit(func(s *stamp.Stamp) { s.TS = json.MaxSafe + 1 }),
		"a padded sig":           edit(func(s *stamp.Stamp) { s.Sig = "a=" }),
		"a sig off the alphabet": edit(func(s *stamp.Stamp) { s.Sig = "!" }),
		"a sig with unused bits": edit(func(s *stamp.Stamp) { s.Sig = "AB" }),
		"a sig with a surrogate": edit(func(s *stamp.Stamp) { s.Sig = surrogate }),
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := bad.Wire(); err == nil {
				t.Fatalf("Stamp.Wire wrote %s", b)
			}
			c := stamp.Chain{s, bad}
			if b, err := c.Wire(); err == nil {
				t.Fatalf("Chain.Wire wrote %s", b)
			}
			if tok, err := c.Token(); err == nil {
				t.Fatalf("Token wrote %s", tok)
			}
		})
	}
	if b, err := stamp.Chain(nil).Wire(); err == nil {
		t.Errorf("Chain.Wire wrote no stamps as %s", b)
	}
	if tok, err := stamp.Chain(nil).Token(); err == nil {
		t.Errorf("Token wrote no stamps as %s", tok)
	}
}

func TestSign(t *testing.T) {
	s := signed(t)
	msg, err := s.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	want := "paztport-stamp\n" +
		`{"bind":"b","ext":"","inst":"pi-1","prev":"","rcv":"next","rid":"rid-1","sess":"s","svc":"pi","ts":1000,"v":4}`
	if string(msg) != want {
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
		{"ext", func(s *stamp.Stamp, v string) { s.Ext = v }},
		{"prev", func(s *stamp.Stamp, v string) { s.Prev = v }},
	}
	if len(setters) != len(signedFields) {
		t.Fatal("a signed field has no setter")
	}
	for _, f := range setters {
		for what, v := range map[string]string{
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

// TestTheSpecsExampleSignsTheSpecsBytes is wire.md's example under Fields and signed bytes, byte for byte.
func TestTheSpecsExampleSignsTheSpecsBytes(t *testing.T) {
	s := stamp.Stamp{Svc: "pi", Inst: "pi-\u00e9", RID: "rid-1", TS: 1767225600000, Sess: "", Rcv: "local:read",
		Bind: "bind-2", Ext: "", Prev: "prev-2"}
	want := "paztport-stamp\n" +
		`{"bind":"bind-2","ext":"","inst":"pi-` + "\u00e9" +
		`","prev":"prev-2","rcv":"local:read","rid":"rid-1","sess":"","svc":"pi","ts":1767225600000,"v":4}`
	got, err := s.SigningBytes()
	if err != nil || string(got) != want {
		t.Fatalf("SigningBytes = %q, %v, want %q", got, err, want)
	}
	if !bytes.Contains(got, []byte{'p', 'i', '-', 0xc3, 0xa9}) {
		t.Fatal("the signed bytes do not hold the UTF-8 of the e with an acute accent")
	}
}

// TestAFieldHoldingThePipeSignsAndVerifies: "|" is a character like any other in the version 4 signed bytes.
func TestAFieldHoldingThePipeSignsAndVerifies(t *testing.T) {
	f := unsaved
	f.RID, f.Inst = "r|1", "i|2"
	s, err := stamp.Sign(f, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifies(t, s, key)
	c, code := stamp.ParseChain(mustWire(t, stamp.Chain{s}))
	if code != reason.OK || c[0] != s {
		t.Fatalf("ParseChain = %+v, %s, want the stamp signed", c, code)
	}
}

// TestStampsDifferingOnlyInWhereAQuoteFallsDoNotShareBytes: two stamps that the same text, unescaped and joined,
// would describe, a quote ending inst in one and prev in the other, sign different bytes, so neither's
// signature verifies for the other. JCS escapes every string, which is what keeps them apart.
func TestStampsDifferingOnlyInWhereAQuoteFallsDoNotShareBytes(t *testing.T) {
	a, b := unsaved, unsaved
	a.Inst, a.Prev = `a","prev":"b`, ""
	b.Inst, b.Prev = "a", `b","prev":"`
	ab, err := a.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	bb, err := b.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if bytes.Equal(ab, bb) {
		t.Fatalf("both stamps sign %q", ab)
	}
	signedA, err := stamp.Sign(a, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig, err := b64.Decode(signedA.Sig)
	if err != nil || keys.Verify(pub, bb, sig) {
		t.Fatal("a's signature verifies over b's signed bytes")
	}
}

// TestANoncharacterOrInvalidUTF8IsNeverSigned: each string field in turn, holding a noncharacter, a lone
// surrogate's bytes or a cut-short rune, has no signed bytes, and Sign refuses it without quoting it.
func TestANoncharacterOrInvalidUTF8IsNeverSigned(t *testing.T) {
	set := map[string]func(*stamp.Stamp, string){
		"svc": func(s *stamp.Stamp, v string) { s.Svc = v }, "inst": func(s *stamp.Stamp, v string) { s.Inst = v },
		"rid": func(s *stamp.Stamp, v string) { s.RID = v }, "sess": func(s *stamp.Stamp, v string) { s.Sess = v },
		"rcv": func(s *stamp.Stamp, v string) { s.Rcv = v }, "bind": func(s *stamp.Stamp, v string) { s.Bind = v },
		"ext": func(s *stamp.Stamp, v string) { s.Ext = v }, "prev": func(s *stamp.Stamp, v string) { s.Prev = v },
	}
	if len(set) != len(signedFields) {
		t.Fatal("a signed field has no setter")
	}
	for name, f := range set {
		for what, v := range map[string]string{
			"U+FDD0":                   "a" + string(rune(0xFDD0)),
			"U+10FFFF":                 "a" + string(rune(0x10FFFF)),
			"a lone surrogate's bytes": "a" + surrogate,
			"a cut-short rune":         "a\xc3",
		} {
			t.Run(name+" with "+what, func(t *testing.T) {
				s := unsaved
				f(&s, v)
				refuses(t, s, key)
				if msg := refusal(t, s); strings.Contains(msg, v) || !strings.Contains(msg, name) {
					t.Errorf("the refusal %q quotes the field or does not name it", msg)
				}
			})
		}
	}
}

// TestTheVersionIsWrittenOnce walks the module's non-test sources: no line outside stamp/stamp.go writes "v" beside
// a 3 or a 4, and in stamp.go the only code line holding a 3 or a 4 is the constant. So the number a stamp is
// written and read with has one home.
func TestTheVersionIsWrittenOnce(t *testing.T) {
	beside := regexp.MustCompile(`"v".*\b[34]\b|\b[34]\b.*"v"`)
	digit := regexp.MustCompile(`\b[34]\b`)
	comment := regexp.MustCompile(`^\s*//`)
	var seen int
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen++
		home := filepath.ToSlash(path) == "../stamp/stamp.go"
		for i, line := range strings.Split(string(b), "\n") {
			if comment.MatchString(line) {
				continue
			}
			switch {
			case home && digit.MatchString(line) && strings.TrimSpace(line) != "const Version = 4":
				t.Errorf("%s:%d writes a 3 or a 4 outside the constant: %s", path, i+1, strings.TrimSpace(line))
			case !home && beside.MatchString(line):
				t.Errorf("%s:%d writes a stamp version: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 30 {
		t.Fatalf("the walk read %d source files; it is not walking the module", seen)
	}
	b, err := os.ReadFile("stamp.go")
	if err != nil || !strings.Contains(string(b), "\nconst Version = 4\n") {
		t.Fatal("stamp.go does not hold the constant")
	}
}

// mustWire returns c's wire bytes.
func mustWire(t *testing.T, c stamp.Chain) []byte {
	t.Helper()
	b, err := c.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
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

// TestResponseBinding pins the version 4 response binding: utf8(resultHash || "\n" || callID), with no labels
// (wire.md, Bindings). v4.json's bindResponse gives the hash; the parts are refused when they could run into each
// other or have no UTF-8 form.
func TestResponseBinding(t *testing.T) {
	got, err := stamp.ResponseBinding("result-hash", "call-1")
	if err != nil || got != "Ecs64bp8x8_Ehoe7svvulYX563R0KNdS25sfSg0hzXw" {
		t.Fatalf("ResponseBinding = %s, %v", got, err)
	}
	sum := sha256.Sum256([]byte("result-hash\ncall-1"))
	if got != b64.Encode(sum[:]) {
		t.Fatal("ResponseBinding is not the hash of the result hash, a newline and the call id")
	}
	for name, args := range map[string][2]string{
		"a newline in the call id":            {"rh", "call\n1"},
		"a call id ending in a newline":       {"rh", "call-1\n"},
		"a lone surrogate in the result hash": {"rh" + surrogate, "call-1"},
		"a lone surrogate in the call id":     {"rh", "call-" + surrogate},
		"a cut-short rune in the call id":     {"rh", "call-\xc3"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := stamp.ResponseBinding(args[0], args[1]); err == nil {
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
)

// shaped is a block naming a made-up extension, example, with two items, and requiring it of the receiver.
func shaped(t *testing.T) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{"example": {`{"note":"n1"}`, "7"}}, []string{"example"})
	if err != nil {
		t.Fatalf("NewBlock: %v", err)
	}
	return b
}

// stamper returns svc's stamper, its instance svc-1, signing at now. An origin mints rid; any other
// service mints another, so that a stamp which should carry its inbound chain's rid is seen not to take
// a new one.
func stamper(svc string, k ed25519.PrivateKey, origin bool) *stamp.Stamper {
	minted := "rid-minted-by-" + svc
	if origin {
		minted = rid
	}
	return &stamp.Stamper{Svc: svc, Inst: svc + "-1", Key: k, Origin: origin,
		NewRID: func() string { return minted }, Now: func() int64 { return now }}
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
	block := shaped(t)
	ignored := stamp.Chain{signed(t)}
	c, p, err := stamper("gateway", gatewayKey, true).Next(ignored, "orders", "b1", block, bundle("gateway/orders"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("the origin's chain has %d stamps, want 1", len(c))
	}
	want := stamp.Stamp{Svc: "gateway", Inst: "gateway-1", RID: rid, TS: now, Sess: "", Rcv: "orders", Bind: "b1",
		Ext: block.Commit(), Prev: "", Sig: c[0].Sig}
	if c[0] != want {
		t.Fatalf("the origin stamp is %+v, want %+v", c[0], want)
	}
	verifies(t, c[0], gatewayKey)
	proofFor(t, p, "gateway/orders")
}

// TestNextAppends appends to a two-stamp chain whose stamps differ in rid and sess, as no verified chain
// does, to show where each comes from: the rid is the origin's, and the sess the last stamp's.
func TestNextAppends(t *testing.T) {
	origin, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", stamp.EmptyBlock, bundle())
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
	c, p, err := payment.Next(roomy, "bank", "b3", stamp.EmptyBlock, bundle("gateway/orders/payment/bank"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(c) != 3 || !slices.Equal(c[:2], inbound) {
		t.Fatalf("the chain is %+v, want the inbound stamps then one more", c)
	}
	want := stamp.Stamp{Svc: "payment", Inst: "payment-1", RID: rid, TS: now, Sess: "sess-1", Rcv: "bank", Bind: "b3",
		Ext: "", Prev: hop.Sig, Sig: c[2].Sig}
	if c[2] != want {
		t.Fatalf("the appended stamp is %+v, want %+v", c[2], want)
	}
	verifies(t, c[2], paymentKey)
	proofFor(t, p, "gateway/orders/payment/bank")
	if !slices.Equal(roomy[:cap(roomy)], kept) {
		t.Fatal("Next wrote into the inbound chain's spare capacity")
	}

	_, p, err = payment.Next(inbound, "search", "b3", stamp.EmptyBlock, bundle("gateway/orders/payment/bank"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	proofFor(t, p, "")
}

func TestNextRefuses(t *testing.T) {
	orders := stamper("orders", ordersKey, false)
	inbound := stamp.Chain{signed(t)}
	for name, f := range map[string]func() error{
		"no inbound chain": func() error {
			_, _, err := orders.Next(nil, "payment", "b", stamp.EmptyBlock, bundle())
			return err
		},
		"an empty inbound chain": func() error {
			_, _, err := orders.Next(stamp.Chain{}, "payment", "b", stamp.EmptyBlock, bundle())
			return err
		},
		"a delimiter in the receiver": func() error {
			_, _, err := orders.Next(inbound, "pay|ment", "b", stamp.EmptyBlock, bundle())
			return err
		},
		"no clock": func() error {
			s := *orders
			s.Now = nil
			_, _, err := s.Next(inbound, "payment", "b", stamp.EmptyBlock, bundle())
			return err
		},
		"an origin with no rid": func() error {
			s := *stamper("gateway", gatewayKey, true)
			s.NewRID = nil
			_, _, err := s.Next(nil, "orders", "b", stamp.EmptyBlock, bundle())
			return err
		},
		"a clock past 2^53 - 1": func() error {
			s := *orders
			s.Now = func() int64 { return json.MaxSafe + 1 }
			_, _, err := s.Next(inbound, "payment", "b", stamp.EmptyBlock, bundle())
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
	block := shaped(t)
	internal, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", stamp.EmptyBlock, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	orders := stamper("orders", ordersKey, false)
	c, p, err := orders.Boundary(internal, "sess-1", "psp", "b3", block, bundle("orders/psp", "gateway/orders/psp"))
	if err != nil {
		t.Fatalf("Boundary: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("the boundary chain has %d stamps, want 1", len(c))
	}
	want := stamp.Stamp{Svc: "orders", Inst: "orders-1", RID: rid, TS: now, Sess: "sess-1", Rcv: "psp", Bind: "b3",
		Ext: block.Commit(), Prev: "", Sig: c[0].Sig}
	if c[0] != want {
		t.Fatalf("the boundary stamp is %+v, want %+v", c[0], want)
	}
	verifies(t, c[0], ordersKey)
	proofFor(t, p, "orders/psp")

	_, p, err = orders.Boundary(internal, "sess-1", "psp", "b3", stamp.EmptyBlock, bundle("gateway/orders/psp"))
	if err != nil {
		t.Fatalf("Boundary: %v", err)
	}
	proofFor(t, p, "")

	if _, _, err := orders.Boundary(internal, "", "psp", "b3", stamp.EmptyBlock, bundle()); err == nil {
		t.Error("Boundary stamped a call in no session, which would be a valid in-mesh origin stamp")
	}
	for _, none := range []stamp.Chain{nil, {}} {
		if _, _, err := orders.Boundary(none, "sess-1", "psp", "b3", stamp.EmptyBlock, bundle()); err == nil {
			t.Error("Boundary stamped a call with no internal chain")
		}
	}
}

// TestRespond responds to a two-stamp chain whose stamps differ in rid and sess, as no verified chain
// does, to show where each field comes from: the rid is the origin's, and the sess, rcv and prev the last
// stamp's, so the response names the caller.
func TestRespond(t *testing.T) {
	origin, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", stamp.EmptyBlock, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	hop := stamp.Stamp{Svc: "orders", Inst: "orders-1", RID: "rid-other", TS: now, Sess: "sess-1", Rcv: "payment",
		Bind: "b2", Prev: origin[0].Sig}
	if hop, err = stamp.Sign(hop, ordersKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	request := stamp.Chain{origin[0], hop}

	block := shaped(t)
	payment := stamper("payment", paymentKey, false)
	payment.Now = func() int64 { return now + 5 }
	s, err := payment.Respond(request, "rh", rid, block)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	bind, err := stamp.ResponseBinding("rh", rid)
	if err != nil {
		t.Fatalf("ResponseBinding: %v", err)
	}
	want := stamp.Stamp{Svc: "payment", Inst: "payment-1", RID: rid, TS: now + 5, Sess: "sess-1", Rcv: "orders",
		Bind: bind, Ext: block.Commit(), Prev: hop.Sig, Sig: s.Sig}
	if s != want {
		t.Fatalf("the response stamp is %+v, want %+v", s, want)
	}
	verifies(t, s, paymentKey)

	for _, none := range []stamp.Chain{nil, {}} {
		if _, err := payment.Respond(none, "rh", rid, stamp.EmptyBlock); err == nil {
			t.Error("Respond stamped a response to no request")
		}
	}
	if _, err := payment.Respond(request, "rh", "call\n1", stamp.EmptyBlock); err == nil {
		t.Error("Respond stamped a response whose binding can't be computed")
	}
}

// TestAnOriginNeverResponds checks the rule that keeps a response stamp from minting origin stamps. A
// response is shaped like a request stamp, so an origin's response to a forged one-stamp chain with an
// empty sig has prev "" and would be a valid origin stamp, addressed to whichever service the forgery
// named.
func TestAnOriginNeverResponds(t *testing.T) {
	forged := stamp.Chain{{Svc: "orders", Inst: "x", RID: rid, TS: now, Rcv: "gateway", Bind: "b"}}
	if s, err := stamper("gateway", gatewayKey, true).Respond(forged, "h", rid, stamp.EmptyBlock); err == nil {
		t.Fatalf("the origin responded with %+v", s)
	}
}

// TestStamperRefusesWhatIsNotARouteNode: a stamp names its signer and its receiver as route nodes, and one
// that is not a node (empty, a dot, with a separator) could never be on a verified route. Next, Boundary
// and Respond refuse it, sign nothing, and do not quote it.
func TestStamperRefusesWhatIsNotARouteNode(t *testing.T) {
	inbound := stamp.Chain{signed(t)}
	named := func(svc string) *stamp.Stamper { return stamper(svc, ordersKey, false) }
	for _, bad := range []string{"", ".", "a/b"} {
		for name, f := range map[string]func() (stamp.Chain, error){
			"Next with svc": func() (stamp.Chain, error) {
				c, _, err := named(bad).Next(inbound, "payment", "b", stamp.EmptyBlock, bundle())
				return c, err
			},
			"Next with rcv": func() (stamp.Chain, error) {
				c, _, err := named("orders").Next(inbound, bad, "b", stamp.EmptyBlock, bundle())
				return c, err
			},
			"Boundary with svc": func() (stamp.Chain, error) {
				c, _, err := named(bad).Boundary(inbound, "sess-1", "psp", "b", stamp.EmptyBlock, bundle())
				return c, err
			},
			"Boundary with partner": func() (stamp.Chain, error) {
				c, _, err := named("orders").Boundary(inbound, "sess-1", bad, "b", stamp.EmptyBlock, bundle())
				return c, err
			},
			"Respond with svc": func() (stamp.Chain, error) {
				s, err := named(bad).Respond(inbound, "rh", rid, stamp.EmptyBlock)
				if s != (stamp.Stamp{}) {
					return stamp.Chain{s}, err
				}
				return nil, err
			},
			// A forged inbound, signed as the low-level Sign allows: its last svc is the response's rcv.
			"Respond with rcv": func() (stamp.Chain, error) {
				forged := unsaved
				forged.Svc = bad
				last, err := stamp.Sign(forged, ordersKey)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				s, err := named("orders").Respond(stamp.Chain{last}, "rh", rid, stamp.EmptyBlock)
				if s != (stamp.Stamp{}) {
					return stamp.Chain{s}, err
				}
				return nil, err
			},
		} {
			t.Run(name+" "+bad, func(t *testing.T) {
				c, err := f()
				if err == nil {
					t.Fatalf("stamped %+v", c)
				}
				if len(bad) > 1 && strings.Contains(err.Error(), bad) {
					t.Errorf("the error quotes the value: %v", err)
				}
				if len(c) != 0 {
					t.Errorf("returned %+v with an error", c)
				}
			})
		}
	}
}

// TestRouteOf builds a route from the first stamp's svc and each stamp's rcv, so an operation a hop names is
// part of it, and leaves off the last rcv when the receiver is not in the route.
func TestRouteOf(t *testing.T) {
	c := stamp.Chain{
		{Svc: "gateway", Rcv: "orders#createOrder"},
		{Svc: "orders", Rcv: "payment#charge"},
	}
	for _, tt := range []struct {
		name    string
		chain   stamp.Chain
		inRoute bool
		want    string
	}{
		{"with the receiver", c, true, "gateway/orders#createOrder/payment#charge"},
		{"without the receiver", c, false, "gateway/orders#createOrder"},
		{"a bare rcv", stamp.Chain{{Svc: "gateway", Rcv: "orders"}}, true, "gateway/orders"},
		{"one stamp, no receiver", stamp.Chain{{Svc: "gateway", Rcv: "orders"}}, false, "gateway"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := stamp.RouteOf(tt.chain, tt.inRoute); got != tt.want {
				t.Fatalf("RouteOf = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNextLooksUpTheRouteFromRcv finds the proof by the route the chain's rcv values name, so an operation a
// hop names selects the proof for that operation's route.
func TestNextLooksUpTheRouteFromRcv(t *testing.T) {
	gateway := stamper("gateway", gatewayKey, true)
	origin, _, err := gateway.Next(nil, "orders#createOrder", "b1", stamp.EmptyBlock, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	b := bundle("gateway/orders#createOrder/payment#charge", "gateway/orders/payment")
	_, p, err := stamper("orders", ordersKey, false).Next(origin, "payment#charge", "b2", stamp.EmptyBlock, b)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	proofFor(t, p, "gateway/orders#createOrder/payment#charge")

	_, p, err = stamper("orders", ordersKey, false).Next(origin, "payment#refund", "b2", stamp.EmptyBlock, b)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	proofFor(t, p, "")
}

// TestStamperRefusesHashInSvc refuses to sign as a service whose name holds '#', which would imitate a
// service and operation.
func TestStamperRefusesHashInSvc(t *testing.T) {
	_, _, err := stamper("orders#createOrder", ordersKey, true).Next(nil, "payment", "b1", stamp.EmptyBlock, bundle())
	if err == nil {
		t.Fatal("Next signed as a service named with '#'")
	}
	if !strings.Contains(err.Error(), "svc") {
		t.Errorf("Next = %v, want a refusal of the svc", err)
	}
}

// TestStamperRefusesMalformedRcv refuses to sign a receiver that is not a service, or a service, '#' and an
// operation name.
func TestStamperRefusesMalformedRcv(t *testing.T) {
	for _, rcv := range []string{"payment#", "a#b#c", "#pay"} {
		_, _, err := stamper("gateway", gatewayKey, true).Next(nil, rcv, "b1", stamp.EmptyBlock, bundle())
		if err == nil {
			t.Errorf("Next signed for the rcv %q", rcv)
		} else if !strings.Contains(err.Error(), "rcv") {
			t.Errorf("Next(%q) = %v, want a refusal of the rcv", rcv, err)
		}
	}
}

// TestTheStampCommitsToItsBlock: Next, Boundary and Respond each sign their block's commitment as ext, which is
// "" for the empty block and the block's hash otherwise (wire.md, Blocks).
func TestTheStampCommitsToItsBlock(t *testing.T) {
	origin, _, err := stamper("gateway", gatewayKey, true).Next(nil, "orders", "b1", stamp.EmptyBlock, bundle())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	orders := stamper("orders", ordersKey, false)
	named, err := stamp.NewBlock(map[string][]string{"example": {}}, nil)
	if err != nil {
		t.Fatalf("NewBlock: %v", err)
	}
	for name, block := range map[string]stamp.Block{
		"the empty block": stamp.EmptyBlock, "a block naming example with nothing": named, "a block with items": shaped(t),
	} {
		t.Run(name, func(t *testing.T) {
			want := block.Commit()
			if (block.Commit() == "") != (name == "the empty block") {
				t.Fatalf("the block commits to %q", want)
			}
			c, _, err := orders.Next(origin, "payment", "b2", block, bundle())
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			b, _, err := orders.Boundary(origin, "sess-1", "psp", "b3", block, bundle())
			if err != nil {
				t.Fatalf("Boundary: %v", err)
			}
			r, err := orders.Respond(origin, "rh", rid, block)
			if err != nil {
				t.Fatalf("Respond: %v", err)
			}
			for what, s := range map[string]stamp.Stamp{"Next": c[1], "Boundary": b[0], "Respond": r} {
				if s.Ext != want {
					t.Errorf("%s signed ext %q, want %q", what, s.Ext, want)
				}
				verifies(t, s, ordersKey)
			}
		})
	}
}

// TestStamperImportsNoExtension: the core commits to a block and never reads an item, so no file of the stamp
// package, its tests included, imports an extension.
func TestStamperImportsNoExtension(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) < 5 {
		t.Fatalf("the package's files: %v, %v", files, err)
	}
	for _, f := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); strings.HasSuffix(path, "/influence") {
				t.Errorf("%s imports %s", f, path)
			}
		}
	}
}
