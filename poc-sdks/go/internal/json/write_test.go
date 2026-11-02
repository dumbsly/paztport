// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// TestMemberOrderIsUTF16 pins the spec's example: U+1F600 is the code units D83D DE00, so it sorts before
// U+FB33, though its code point is greater.
func TestMemberOrderIsUTF16(t *testing.T) {
	v := json.Obj(
		json.Member{Name: "\uFB33", Value: json.I(1)},
		json.Member{Name: "\U0001F600", Value: json.I(0)},
	)
	got, err := json.Wire(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"\U0001F600\":0,\"\uFB33\":1}"; string(got) != want {
		t.Fatalf("Wire = %+q, want %+q", got, want)
	}
	_, err = json.ReadWire([]byte("{\"\uFB33\":1,\"\U0001F600\":0}"))
	if step(err) != json.StepCanonical {
		t.Fatalf("ReadWire of the members in code point order = %v, want a canonical refusal", err)
	}
}

func TestLessUTF16(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"a", "b", true},
		{"b", "a", false},
		{"a", "a", false},
		{"", "a", true},
		{"a", "", false},
		{"", "", false},
		{"a", "ab", true},
		{"ab", "a", false},
		{"Z", "a", true},
		{"1", "10", true},
		{"10", "2", true},
		{"\u00e9", "z", false},
		{"\U0001F600", "\uFB33", true},
		{"\uFB33", "\U0001F600", false},
		{"\U00010000", "\uFFFF", true},
		{"\uE000", "\U0010FFFF", false},
		{"\uD7FF", "\U00010000", true},
		{"\U0001F600", "\U0001F601", true},
		{"\U0001F601", "\U0001F600", false},
		{"\U0001F600", "\U00020000", true},
		{"x\U0001F600", "x\uFB33", true},
	} {
		if got := json.LessUTF16(c.a, c.b); got != c.less {
			t.Errorf("LessUTF16(%+q, %+q) = %v, want %v", c.a, c.b, got, c.less)
		}
	}
}

// TestWriterRefuses checks that each writer refuses, whole, a value a reader would refuse.
func TestWriterRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		v    json.Value
	}{
		{"a lone high surrogate, as its WTF-8 bytes", json.S("\xed\xa0\x80")},
		{"a lone low surrogate in a member name", json.Obj(json.Member{Name: "\xed\xb0\x80", Value: json.Null()})},
		{"a byte that starts no sequence", json.S("a\xffb")},
		{"an overlong form", json.S("\xc0\x80")},
		{"the noncharacter U+FFFE", json.S("\uFFFE")},
		{"the noncharacter U+10FFFF, deep inside", json.Arr(json.Obj(json.Member{Name: "a", Value: json.S("x\U0010FFFF")}))},
		{"the noncharacter U+FDD0 in a member name", json.Obj(json.Member{Name: "\uFDD0", Value: json.Null()})},
		{"a negative integer", json.I(-1)},
		{"2^53", json.I(json.MaxSafe + 1)},
		{"a repeated member name", json.Obj(json.Member{Name: "a", Value: json.I(1)}, json.Member{Name: "a", Value: json.I(2)})},
		{"33 nested arrays", arrays(33)},
		{"33 nested objects", objects(33)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if b, err := json.Wire(c.v); step(err) != json.StepWrite {
				t.Errorf("Wire = %+q, %v; want a write refusal", b, err)
			}
			if s, err := json.Token(c.v); step(err) != json.StepWrite {
				t.Errorf("Token = %q, %v; want a write refusal", s, err)
			}
			if b, err := json.File(c.v); step(err) != json.StepWrite {
				t.Errorf("File = %+q, %v; want a write refusal", b, err)
			}
		})
	}
}

func TestWriterLimits(t *testing.T) {
	for _, c := range []struct {
		name  string
		write func(json.Value) (int, error)
		v     json.Value
		size  int // the length written, or 0 for a refusal
	}{
		{"32 nested arrays", wireLength, arrays(32), 64},
		{"32 nested objects as a file", fileLength, objects(32), 2204},
		{"wire bytes at the limit", wireLength, quoted(json.WireBytes), json.WireBytes},
		{"wire bytes one past it", wireLength, quoted(json.WireBytes + 1), 0},
		{"a token of wire bytes at the limit", tokenLength, quoted(json.WireBytes), json.TokenText},
		{"a token of wire bytes one past it", tokenLength, quoted(json.WireBytes + 1), 0},
		{"a file at the limit, its final newline included", fileLength, quoted(json.FileBytes - 1), json.FileBytes},
		{"a file one past it", fileLength, quoted(json.FileBytes), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, err := c.write(c.v)
			switch {
			case c.size == 0 && step(err) != json.StepWrite:
				t.Fatalf("got %v, want a write refusal", err)
			case c.size != 0 && err != nil:
				t.Fatalf("refused: %v", err)
			case n != c.size:
				t.Fatalf("wrote %d, want %d", n, c.size)
			}
		})
	}
}

// TestEscapes pins RFC 8785 §3.2.2.2: the two-character escapes for the characters they name, \u00xx in
// lowercase for the other control characters, and every other character as itself.
func TestEscapes(t *testing.T) {
	short := map[byte]string{'\b': `\b`, '\t': `\t`, '\n': `\n`, '\f': `\f`, '\r': `\r`}
	const digits = "0123456789abcdef"
	for c := range byte(0x20) {
		want, ok := short[c]
		if !ok {
			want = `\u00` + string(digits[c>>4]) + string(digits[c&0xf])
		}
		got, err := json.Wire(json.S(string([]byte{c})))
		if err != nil {
			t.Fatalf("Wire refused the control character %#x: %v", c, err)
		}
		if string(got) != `"`+want+`"` {
			t.Errorf("Wire wrote the control character %#x as %+q, want %+q", c, got, `"`+want+`"`)
		}
	}
	for _, c := range []struct{ in, want string }{
		{`"`, `"\""`},
		{`\`, `"\\"`},
		{"/", `"/"`},
		{"\x7f", "\"\x7f\""},
		{"\u00e9\u2028\U0001F600", "\"\u00e9\u2028\U0001F600\""},
		{"\uFDCF\uFDF0", "\"\uFDCF\uFDF0\""},
	} {
		got, err := json.Wire(json.S(c.in))
		if err != nil {
			t.Fatalf("Wire refused %+q: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("Wire(%+q) = %+q, want %+q", c.in, got, c.want)
		}
	}
}

func TestWireForm(t *testing.T) {
	v := json.Obj(
		json.Member{Name: "b", Value: json.Arr(json.I(0), json.I(json.MaxSafe), json.B(true), json.B(false), json.Null())},
		json.Member{Name: "a", Value: json.Obj(json.Member{Name: "y", Value: json.Arr()}, json.Member{Name: "x", Value: json.Obj()})},
		json.Member{Name: "c", Value: json.S("")},
	)
	got, err := json.Wire(v)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"a":{"x":{},"y":[]},"b":[0,9007199254740991,true,false,null],"c":""}`
	if string(got) != want {
		t.Fatalf("Wire = %s, want %s", got, want)
	}
	tok, err := json.Token(v)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := json.ReadToken(tok); err != nil {
		t.Fatalf("ReadToken refused the token Token wrote: %v", err)
	} else if again, _ := json.Wire(back); string(again) != want {
		t.Fatalf("the token reads as %s, want %s", again, want)
	}
}

func TestFileForm(t *testing.T) {
	for _, c := range []struct {
		name string
		v    json.Value
		want string
	}{
		{"nested, with empties", json.Obj(
			json.Member{Name: "b", Value: json.Obj(json.Member{Name: "c", Value: json.B(true)})},
			json.Member{Name: "a", Value: json.Arr(json.I(1), json.Arr(), json.Obj(), json.Arr(json.S("x")))},
		), "{\n  \"a\": [\n    1,\n    [],\n    {},\n    [\n      \"x\"\n    ]\n  ],\n  \"b\": {\n    \"c\": true\n  }\n}\n"},
		{"a string at the top level", json.S("x\n"), "\"x\\n\"\n"},
		{"an empty array", json.Arr(), "[]\n"},
		{"null", json.Null(), "null\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := json.File(c.v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("File wrote\n%s\nwant\n%s", got, c.want)
			}
		})
	}
}

// TestValuesDoNotChange checks that a Value shares no slice with its builder or its readers.
func TestValuesDoNotChange(t *testing.T) {
	members := []json.Member{{Name: "a", Value: json.I(1)}}
	o := json.Obj(members...)
	members[0].Name = "b"
	o.Members()[0].Name = "c"
	if got := o.Members()[0].Name; got != "a" {
		t.Errorf("the object's member is now %q, want a", got)
	}
	items := []json.Value{json.I(1)}
	a := json.Arr(items...)
	items[0] = json.I(2)
	a.Items()[0] = json.I(3)
	if got := a.Items()[0].Int(); got != 1 {
		t.Errorf("the array's item is now %d, want 1", got)
	}
}

func TestAccessorsOfAnotherKind(t *testing.T) {
	for _, v := range []json.Value{json.Null(), json.B(true), json.I(7), json.S("x"), json.Arr(json.I(1)), json.Obj(json.Member{Name: "a"})} {
		k := v.Kind()
		if k != json.KindString && v.Str() != "" ||
			k != json.KindInt && v.Int() != 0 ||
			k != json.KindBool && v.Bool() ||
			k != json.KindArray && v.Items() != nil ||
			k != json.KindObject && v.Members() != nil {
			t.Errorf("a %v answers an accessor of another kind with other than its zero value", k)
		}
	}
	var zero json.Value
	if zero.Kind() != json.KindNull {
		t.Errorf("the zero Value is a %v, want null", zero.Kind())
	}
}

// step returns the step of err, a refusal, or "" if err is not one.
func step(err error) json.Step {
	var e *json.Error
	if errors.As(err, &e) {
		return e.Step
	}
	return ""
}

// arrays returns n nested arrays: arrays(1) is [], arrays(2) is [[]].
func arrays(n int) json.Value {
	v := json.Arr()
	for range n - 1 {
		v = json.Arr(v)
	}
	return v
}

// objects returns n nested objects: objects(1) is {}, objects(2) is {"a":{}}.
func objects(n int) json.Value {
	v := json.Obj()
	for range n - 1 {
		v = json.Obj(json.Member{Name: "a", Value: v})
	}
	return v
}

// quoted returns a string whose wire bytes are n bytes long, its quotes included.
func quoted(n int) json.Value {
	return json.S(strings.Repeat("a", n-2))
}

func wireLength(v json.Value) (int, error) {
	b, err := json.Wire(v)
	return len(b), err
}

func tokenLength(v json.Value) (int, error) {
	s, err := json.Token(v)
	return len(s), err
}

func fileLength(v json.Value) (int, error) {
	b, err := json.File(v)
	return len(b), err
}
