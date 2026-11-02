// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json_test

import (
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// TestRefusalsNameTheRule checks each parse refusal's rule and offset. Where a text breaks two rules, the
// one the spec checks first answers: a number is refused at its minus sign, then at a seventeenth digit,
// then for a leading zero, then for a fraction or exponent; nesting is refused before the nested value is
// read, so 33 open brackets with nothing after are refused for depth.
func TestRefusalsNameTheRule(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"\xef\xbb\xbf{}", "a byte order mark at byte 0"},
		{"", "no value at byte 0"},
		{" \n", "no value at byte 2"},
		{"tru", "no value at byte 0"},
		{"nul", "no value at byte 0"},
		{"[1,]", "no value at byte 3"},
		{"{}{}", "text after the value at byte 2"},
		{"{} x", "text after the value at byte 3"},
		{"[1 2]", "expected ',' or ']' at byte 3"},
		{"[1", "expected ',' or ']' at byte 2"},
		{`{"a" 1}`, "expected ':' at byte 5"},
		{`{"a":1 "b":2}`, "expected ',' or '}' at byte 7"},
		{`{"a":1,}`, "expected a member name at byte 7"},
		{`{a:1}`, "expected a member name at byte 1"},
		{`{"a":1,"b":2,"a":3}`, "a repeated member name at byte 13"},
		{`{"a":1,"\u0061":2}`, "a repeated member name at byte 7"},
		{`"abc`, "a string not closed, from byte 0"},
		{"\"a\x1fb\"", "a raw control character at byte 2"},
		{"\"a\xc0\x80\"", "invalid UTF-8 at byte 2"},
		{"\"a\xed\xa0\x80\"", "invalid UTF-8 at byte 2"},
		{"\"a\xe2\x82\"", "invalid UTF-8 at byte 2"},
		{"\"a\xef\xbf\xbe\"", "a noncharacter at byte 2"},
		{"{\"\xef\xb7\x90\":1}", "a noncharacter at byte 2"},
		{`"a\x"`, "an escape RFC 8259 does not define at byte 2"},
		{`"a\`, "an escape cut short at byte 2"},
		{`"\`, "an escape cut short at byte 1"},
		{`"a\u12"`, `an escape \u without four hex digits at byte 2`},
		{`"a\u12`, `an escape \u without four hex digits at byte 2`},
		{`"a\ud800"`, "a lone surrogate at byte 2"},
		{`"a\udc00"`, "a lone surrogate at byte 2"},
		{`"a\ud800\u0041"`, "a lone surrogate at byte 2"},
		{`"a\ud800\ud800"`, "a lone surrogate at byte 2"},
		{`"a\ud800\u12"`, `an escape \u without four hex digits at byte 8`},
		{`"a\uffff"`, "a noncharacter at byte 2"},
		{`"a\uFDD0"`, "a noncharacter at byte 2"},
		{`"a\udbff\udfff"`, "a noncharacter at byte 2"},
		{"-1", "a negative number at byte 0"},
		{"-x", "a negative number at byte 0"},
		{"[0,-0]", "a negative number at byte 3"},
		{"10000000000000000", "a 17th digit at byte 16"},
		{"01234567890123456", "a 17th digit at byte 16"},
		{"1234567890123456.5", "a fraction or exponent at byte 16"},
		{"01.5", "a leading zero at byte 0"},
		{"00", "a leading zero at byte 0"},
		{"1.5", "a fraction or exponent at byte 1"},
		{"1e3", "a fraction or exponent at byte 1"},
		{"1E3", "a fraction or exponent at byte 1"},
		{"0.0", "a fraction or exponent at byte 1"},
		{"9007199254740992", "an integer above 2^53 - 1 at byte 0"},
		{"[9999999999999999]", "an integer above 2^53 - 1 at byte 1"},
		{strings.Repeat("[", 33), "nesting deeper than 32 at byte 32"},
		{strings.Repeat(`{"a":`, 32) + "{", "nesting deeper than 32 at byte 160"},
	} {
		_, err := json.ReadFile([]byte(c.in))
		if step(err) != json.StepParse || !strings.HasSuffix(err.Error(), ": "+c.want) {
			t.Errorf("ReadFile(%+q) = %v, want the parse refusal %q", c.in, err, c.want)
		}
	}
}

// TestReplacementCharacterReads checks that U+FFFD, a character like any other, reads raw and escaped: only
// a byte that is not UTF-8 is refused, though Go's decoder answers U+FFFD for both.
func TestReplacementCharacterReads(t *testing.T) {
	const replacement = "\xef\xbf\xbd" // U+FFFD in UTF-8
	escaped := `"` + `\` + `ufffd"`
	for _, c := range []struct {
		name string
		read func([]byte) (json.Value, error)
		in   string
	}{
		{"raw, as wire bytes", json.ReadWire, `"` + replacement + `"`},
		{"escaped, in a file", json.ReadFile, escaped},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.read([]byte(c.in))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if v.Str() != replacement {
				t.Fatalf("read %+q, want U+FFFD", v.Str())
			}
		})
	}
}

func TestReadWireSteps(t *testing.T) {
	for _, c := range []struct {
		name, in string
		step     json.Step
		want     string
	}{
		{"whitespace", `{"a": 1}`, json.StepCanonical, "not the canonical bytes, from byte 5"},
		{"members out of order", `{"b":1,"a":2}`, json.StepCanonical, "not the canonical bytes, from byte 2"},
		{"an escape JCS does not write", `["\/"]`, json.StepCanonical, "not the canonical bytes, from byte 2"},
		{"a repeated name, refused at parse though not canonical either", `{"b":1,"b":2}`, json.StepParse, "a repeated member name at byte 7"},
		{"over the limit, though not JSON at all", strings.Repeat("x", json.WireBytes+1), json.StepSize, "the wire bytes are over the 262144-byte limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := json.ReadWire([]byte(c.in))
			if step(err) != c.step || !strings.HasSuffix(err.Error(), ": "+c.want) {
				t.Fatalf("ReadWire = %v, want the %s refusal %q", err, c.step, c.want)
			}
		})
	}
}

func TestReadTokenSteps(t *testing.T) {
	for _, c := range []struct {
		name, in string
		step     json.Step
	}{
		{"text one past the limit", strings.Repeat("A", json.TokenText+1), json.StepSize},
		// 349526 characters decode to 262144 zero bytes, which is not JSON: the text was read.
		{"text at the limit", strings.Repeat("A", json.TokenText), json.StepParse},
		{"padding", "e30=", json.StepParse},
		{"a character outside the alphabet", "e30+", json.StepParse},
		{"non-zero unused bits", "e31", json.StepParse},
		{"JSON in place of its token", "{}", json.StepParse},
		{"the token of a non-canonical value", "eyJhIjogMX0", json.StepCanonical},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := json.ReadToken(c.in); step(err) != c.step {
				t.Fatalf("ReadToken = %v, want a %s refusal", err, c.step)
			}
		})
	}
	v, err := json.ReadToken("e30")
	if err != nil || v.Kind() != json.KindObject || len(v.Members()) != 0 {
		t.Fatalf("ReadToken(e30) = %v, %v; want {}", v, err)
	}
}

func TestReadFileLimit(t *testing.T) {
	_, err := json.ReadFile([]byte(strings.Repeat(" ", json.FileBytes+1)))
	if step(err) != json.StepSize || !strings.HasSuffix(err.Error(), ": the file is over the 1048576-byte limit") {
		t.Fatalf("ReadFile = %v, want the size refusal", err)
	}
}

// TestErrorsDoNotQuoteTheInput reads texts that each hold a secret where the wire reader refuses them, and
// checks that no refusal quotes it.
func TestErrorsDoNotQuoteTheInput(t *testing.T) {
	const secret = "hunter2"
	for _, in := range []string{
		`{"hunter2":1,"hunter2":2}`,
		"\"hunter2\x01\"",
		`"hunter2\q"`,
		`"hunter2`,
		`{"a":hunter2}`,
		`["hunter2" "x"]`,
		`{"hunter2": 1}`,
		`{"b":"hunter2","a":1}`,
		`hunter2`,
	} {
		_, err := json.ReadWire([]byte(in))
		if err == nil {
			t.Errorf("ReadWire read %q", in)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("the wire refusal of %q quotes it: %v", in, err)
		}
		if _, err := json.ReadFile([]byte(in)); err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("the file refusal of %q quotes it: %v", in, err)
		}
		if _, err := json.ReadToken(in); err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal of the token %q quotes it: %v", in, err)
		}
	}
}

func TestExactly(t *testing.T) {
	ab := json.Obj(json.Member{Name: "b", Value: json.I(1)}, json.Member{Name: "a", Value: json.Null()})
	for _, c := range []struct {
		name               string
		o                  json.Value
		required, optional []string
		want               string // the refusal's rule, or "" for none
	}{
		{"every member required, null counting as present", ab, []string{"a", "b"}, nil, ""},
		{"one member optional", ab, []string{"b"}, []string{"a"}, ""},
		{"an optional member absent", ab, []string{"a", "b"}, []string{"c"}, ""},
		{"no member, none required", json.Obj(), nil, []string{"a"}, ""},
		{"the first missing member in sorted order", json.Obj(), []string{"z", "b", "a"}, nil, `the member "a" is missing`},
		{"missing comes before other", json.Obj(json.Member{Name: "hunter2"}), []string{"a"}, nil, `the member "a" is missing`},
		{"a member it does not have", json.Obj(json.Member{Name: "a"}, json.Member{Name: "hunter2"}), []string{"a"}, nil, "member 1 is not one the object has"},
		{"a repeated member", json.Obj(json.Member{Name: "a"}, json.Member{Name: "a"}), []string{"a"}, nil, `the member "a" is repeated`},
		{"an array", json.Arr(), nil, nil, "the value is not an object"},
		{"a string", json.S("hunter2"), nil, nil, "the value is not an object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := json.Exactly(c.o, c.required, c.optional)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (step(err) != json.StepSchema || !strings.HasSuffix(err.Error(), ": "+c.want)):
				t.Fatalf("Exactly = %v, want the schema refusal %q", err, c.want)
			}
		})
	}
}

func TestMemberReaders(t *testing.T) {
	o := json.Obj(
		json.Member{Name: "s", Value: json.S("hunter2")},
		json.Member{Name: "i", Value: json.I(1234567)},
		json.Member{Name: "b", Value: json.B(true)},
		json.Member{Name: "n", Value: json.Null()},
	)
	if v, ok := json.Field(o, "i"); !ok || v.Int() != 1234567 {
		t.Errorf("Field(i) = %v, %v", v, ok)
	}
	if _, ok := json.Field(o, "x"); ok {
		t.Error("Field found a member the object does not have")
	}
	if _, ok := json.Field(json.Arr(json.S("i")), "i"); ok {
		t.Error("Field found a member of an array")
	}
	if s, err := json.String(o, "s"); err != nil || s != "hunter2" {
		t.Errorf("String(s) = %q, %v", s, err)
	}
	if i, err := json.Integer(o, "i"); err != nil || i != 1234567 {
		t.Errorf("Integer(i) = %d, %v", i, err)
	}
	if b, err := json.Bool(o, "b"); err != nil || !b {
		t.Errorf("Bool(b) = %v, %v", b, err)
	}
	for _, c := range []struct {
		name string
		read func() error
		want string
	}{
		{"String of an integer", func() error { _, err := json.String(o, "i"); return err }, `the member "i" is not a string`},
		{"String of null", func() error { _, err := json.String(o, "n"); return err }, `the member "n" is not a string`},
		{"String of a missing member", func() error { _, err := json.String(o, "x"); return err }, `the member "x" is missing`},
		{"Integer of a string", func() error { _, err := json.Integer(o, "s"); return err }, `the member "s" is not an integer`},
		{"Integer of a missing member", func() error { _, err := json.Integer(o, "x"); return err }, `the member "x" is missing`},
		{"Integer of a negative integer", func() error {
			_, err := json.Integer(json.Obj(json.Member{Name: "i", Value: json.I(-1)}), "i")
			return err
		}, `the member "i" is not a protocol integer`},
		{"Integer of 2^53", func() error {
			_, err := json.Integer(json.Obj(json.Member{Name: "i", Value: json.I(json.MaxSafe + 1)}), "i")
			return err
		}, `the member "i" is not a protocol integer`},
		{"Bool of a string", func() error { _, err := json.Bool(o, "s"); return err }, `the member "s" is not a boolean`},
		{"Bool of a missing member", func() error { _, err := json.Bool(json.S("b"), "b"); return err }, `the member "b" is missing`},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.read()
			if step(err) != json.StepSchema || !strings.HasSuffix(err.Error(), ": "+c.want) {
				t.Fatalf("got %v, want the schema refusal %q", err, c.want)
			}
		})
	}
}

func TestStringMap(t *testing.T) {
	m, err := json.StringMap(json.Obj(json.Member{Name: "x", Value: json.S("1")}, json.Member{Name: "y", Value: json.S("")}))
	if err != nil || len(m) != 2 || m["x"] != "1" || m["y"] != "" {
		t.Fatalf("StringMap = %v, %v", m, err)
	}
	if m, err := json.StringMap(json.Obj()); err != nil || m == nil || len(m) != 0 {
		t.Fatalf("StringMap({}) = %#v, %v; want an empty map", m, err)
	}
	for _, c := range []struct {
		name string
		v    json.Value
		want string
	}{
		{"a value that is not a string", json.Obj(json.Member{Name: "x", Value: json.S("1")}, json.Member{Name: "hunter2", Value: json.I(1)}), "member 1 is not a string"},
		{"a repeated name", json.Obj(json.Member{Name: "hunter2", Value: json.S("1")}, json.Member{Name: "hunter2", Value: json.S("2")}), "member 1 repeats a name"},
		{"an array", json.Arr(json.S("x")), "the value is not an object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := json.StringMap(c.v)
			if step(err) != json.StepSchema || !strings.HasSuffix(err.Error(), ": "+c.want) {
				t.Fatalf("StringMap = %v, want the schema refusal %q", err, c.want)
			}
		})
	}
}
