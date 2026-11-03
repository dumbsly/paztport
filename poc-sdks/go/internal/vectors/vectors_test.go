// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package vectors

import (
	"crypto/ed25519"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// recorder stands in for a test so a check can watch a Node fail one.
type recorder struct {
	testing.TB
	failure string
}

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failure = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// failure runs f against a recorder and returns the message f failed it with, or "" when f did not fail it.
func failure(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(r)
	}()
	<-done
	return r.failure
}

// inline reads text as a vector file named "inline".
func inline(tb testing.TB, text string) Node {
	tb.Helper()
	v, err := parse("inline", []byte(text))
	if err != nil {
		tb.Fatalf("parse: %v", err)
	}
	return Node{tb, v}
}

func TestMembersKeepFileOrderAndText(t *testing.T) {
	n := inline(t, `{"b": 1, "a": [true, null, "x"],
		"c": {"z": 1.5}}`)
	if got, want := n.Names(), []string{"b", "a", "c"}; !slices.Equal(got, want) {
		t.Fatalf("Names = %q, want %q", got, want)
	}
	if got := string(n.Get("a").Raw()); got != `[true, null, "x"]` {
		t.Fatalf("Raw of a = %q", got)
	}
	if got := string(n.Get("c").Get("z").Raw()); got != "1.5" {
		t.Fatalf("Raw of c.z = %q", got)
	}
	if got := string(n.Raw()); !strings.HasPrefix(got, `{"b": 1`) || !strings.HasSuffix(got, `1.5}}`) {
		t.Fatalf("Raw of the whole = %q", got)
	}
	a := n.Get("a")
	if a.Len() != 3 || !a.Index(0).Bool() || !a.Index(1).IsNull() || a.Index(2).Str() != "x" {
		t.Fatalf("a read as %s", a.Raw())
	}
	for _, tc := range []struct {
		n    Node
		want Kind
	}{{n, Object}, {a, Array}, {a.Index(0), Bool}, {a.Index(1), Null}, {a.Index(2), String}, {n.Get("b"), Number}} {
		if tc.n.Kind() != tc.want {
			t.Errorf("Kind of %s = %v, want %v", tc.n.Raw(), tc.n.Kind(), tc.want)
		}
	}
}

func TestLoadKeepsFileOrder(t *testing.T) {
	got := Load(t, "json.json").Names()
	want := []string{"about", "limits", "wire", "file", "fileFormat", "base64url", "jcs", "bindings"}
	if !slices.Equal(got, want) {
		t.Fatalf("json.json's sections = %q, want %q", got, want)
	}
}

func TestStrKeepsLoneSurrogates(t *testing.T) {
	for _, tc := range []struct{ lit, want string }{
		{`"\ud800"`, "\xed\xa0\x80"},
		{`"\uDFFF"`, "\xed\xbf\xbf"},
		{`"\ud83d\ude00"`, "\U0001F600"},
		{`"\uD83D\uDE00"`, "\U0001F600"},
		{`"\udbff\udfff"`, "\U0010FFFF"},
		{`"\ud800\ud800"`, "\xed\xa0\x80\xed\xa0\x80"},
		{`"\ud83d\ud83d\ude00"`, "\xed\xa0\xbd\U0001F600"},
		{`"\ude00\ud83d"`, "\xed\xb8\x80\xed\xa0\xbd"},
		{`"\ud800x"`, "\xed\xa0\x80x"},
		{`"\ud800\u0041"`, "\xed\xa0\x80A"},
		{`"\u00e9 é \u0000"`, "é é \x00"},
		{`"\"\\\/\b\f\n\r\t"`, "\"\\/\b\f\n\r\t"},
		{`"\\ud800"`, `\ud800`},
	} {
		if got := inline(t, tc.lit).Str(); got != tc.want {
			t.Errorf("Str of %s = %q, want %q", tc.lit, got, tc.want)
		}
	}
	got := Load(t, "json.json").Get("bindings").Index(0).Get("inputs").Get("text").Str()
	if want := "fix the \xed\xa0\x80typo"; got != want {
		t.Fatalf("the prompt binding's text = %q, want %q", got, want)
	}
}

func TestMemberNamesAreDecoded(t *testing.T) {
	n := inline(t, `{"\u0061\ud800": 1}`)
	if got := n.Names(); len(got) != 1 || got[0] != "a\xed\xa0\x80" {
		t.Fatalf("Names = %q", got)
	}
}

func TestRepeatedNameIsRefused(t *testing.T) {
	if _, err := parse("inline", []byte(`{"a": 1, "\u0061": 2}`)); err == nil {
		t.Fatal("parse accepted a repeated member name")
	}
}

func TestTextAfterTheValueIsRefused(t *testing.T) {
	for _, text := range []string{`{} {}`, `[] 1`, `"a" "b"`} {
		if _, err := parse("inline", []byte(text)); err == nil {
			t.Errorf("parse accepted %s", text)
		}
	}
}

func TestInt(t *testing.T) {
	n := inline(t, `[9007199254740992, -5, 0, 1.5, 1798761600000.0, 1e3, "1"]`)
	for i, want := range []int64{1 << 53, -5, 0} {
		if got := n.Index(i).Int(); got != want {
			t.Errorf("Int of %s = %d, want %d", n.Index(i).Raw(), got, want)
		}
	}
	for i := 3; i < n.Len(); i++ {
		msg := failure(t, func(tb testing.TB) { n.With(tb).Index(i).Int() })
		if msg == "" {
			t.Errorf("Int of %s did not fail the test", n.Index(i).Raw())
		}
	}
}

func TestStrsAndHex(t *testing.T) {
	n := inline(t, `{"strs": ["a", "", "b"], "none": [], "mixed": ["a", 1], "hex": "00ff7f", "odd": "0f0",
		"notHex": "zz"}`)
	if got := n.Get("strs").Strs(); !slices.Equal(got, []string{"a", "", "b"}) {
		t.Errorf("Strs = %q", got)
	}
	if got := n.Get("none").Strs(); got == nil || len(got) != 0 {
		t.Errorf("Strs of [] = %#v, want an empty list", got)
	}
	if got := n.Get("hex").Hex(); !slices.Equal(got, []byte{0x00, 0xff, 0x7f}) {
		t.Errorf("Hex = %x", got)
	}
	for _, f := range []func(tb testing.TB){
		func(tb testing.TB) { n.With(tb).Get("mixed").Strs() },
		func(tb testing.TB) { n.With(tb).Get("hex").Strs() },
		func(tb testing.TB) { n.With(tb).Get("odd").Hex() },
		func(tb testing.TB) { n.With(tb).Get("notHex").Hex() },
		func(tb testing.TB) { n.With(tb).Get("strs").Hex() },
	} {
		if msg := failure(t, f); msg == "" {
			t.Error("a Node that is not what Strs or Hex reads did not fail the test")
		}
	}
}

func TestMissingFailsTheTestNamingThePlace(t *testing.T) {
	n := inline(t, `{"cases": [{"name": "one"}]}`)
	c := n.Get("cases").Index(0)
	if c.Has("expected") || !c.Has("name") {
		t.Fatal("Has does not report what the case holds")
	}
	msg := failure(t, func(tb testing.TB) { c.With(tb).Get("expected") })
	if !strings.Contains(msg, "inline.cases[0]") || !strings.Contains(msg, `"expected"`) {
		t.Fatalf("Get of a missing member failed with %q", msg)
	}
	if msg := failure(t, func(tb testing.TB) { n.With(tb).Get("cases").Index(1) }); msg == "" {
		t.Fatal("Index past the end did not fail the test")
	}
	if msg := failure(t, func(tb testing.TB) { c.With(tb).Get("name").Int() }); msg == "" {
		t.Fatal("Int of a string did not fail the test")
	}
	if msg := failure(t, func(tb testing.TB) { c.With(tb).Str() }); msg == "" {
		t.Fatal("Str of an object did not fail the test")
	}
}

// TestRewrite checks that Rewrite leaves out the members it drops, keeps the rest in order with their text,
// adds its members after them, and fails the test on a name given twice or text that does not read.
func TestRewrite(t *testing.T) {
	n := inline(t, `{"name": "one", "keyring": {"pi": "pi"}, "now": 1798761600000, "policy": "mesh"}`)
	r := n.Rewrite([]string{"keyring"}, Member{"keyrings", `[{"keyring": {"pi": "pi"}}]`}, Member{"<&>", "null"})
	if got, want := r.Names(), []string{"name", "now", "policy", "keyrings", "<&>"}; !slices.Equal(got, want) {
		t.Fatalf("Names = %q, want %q", got, want)
	}
	if r.Get("now").Int() != 1798761600000 || r.Get("policy").Str() != "mesh" || !r.Get("<&>").IsNull() ||
		r.Get("keyrings").Index(0).Get("keyring").Get("pi").Str() != "pi" {
		t.Fatalf("Rewrite = %s", r.Raw())
	}
	if n.Has("keyrings") || !n.Has("keyring") {
		t.Fatal("Rewrite changed the Node it was called on")
	}
	if msg := failure(t, func(tb testing.TB) { n.With(tb).Rewrite(nil, Member{"now", "1"}) }); msg == "" {
		t.Fatal("Rewrite to a name given twice did not fail the test")
	}
	if msg := failure(t, func(tb testing.TB) { n.With(tb).Rewrite(nil, Member{"x", "{"}) }); msg == "" {
		t.Fatal("Rewrite to text that does not read did not fail the test")
	}
	if msg := failure(t, func(tb testing.TB) { n.With(tb).Get("now").Rewrite(nil) }); msg == "" {
		t.Fatal("Rewrite of a number did not fail the test")
	}
}

func TestEachNamesCases(t *testing.T) {
	var got []string
	inline(t, `[{"name": "one"}, 2, {"name": 3}]`).Each(func(name string, _ Node) { got = append(got, name) })
	if want := []string{"one", "1", "2"}; !slices.Equal(got, want) {
		t.Fatalf("Each named the items %q, want %q", got, want)
	}
	got = nil
	inline(t, `{"z": 1, "a": 2}`).Each(func(name string, n Node) { got = append(got, fmt.Sprint(name, n.Int())) })
	if want := []string{"z1", "a2"}; !slices.Equal(got, want) {
		t.Fatalf("Each visited the members %q, want %q", got, want)
	}
}

func TestV3Key(t *testing.T) {
	for _, name := range []string{"orders", "server-policy", "payment", "search"} {
		priv, pub := V3Key(t, name)
		if !ed25519.Verify(pub, []byte(name), ed25519.Sign(priv, []byte(name))) {
			t.Errorf("V3Key(%q) gives a public key that is not the private key's", name)
		}
	}
	if msg := failure(t, func(tb testing.TB) { V3Key(tb, "nobody") }); msg == "" {
		t.Fatal("V3Key of a key no file lists did not fail the test")
	}
}
