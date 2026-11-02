// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
)

func TestLimits(t *testing.T) {
	limits := vectors.Load(t, "json.json").Get("limits")
	for _, l := range []struct {
		name string
		got  int
	}{
		{"wireBytes", json.WireBytes},
		{"tokenText", json.TokenText},
		{"fileBytes", json.FileBytes},
		{"depth", json.MaxDepth},
	} {
		if want := limits.Get(l.name).Int(); int64(l.got) != want {
			t.Errorf("the %s limit is %d, want %d", l.name, l.got, want)
		}
	}
}

// TestWire reads each wire case as the token of its bytes, by steps 1 to 3. A value that reads writes
// back as the same bytes, since they are canonical.
func TestWire(t *testing.T) {
	vectors.Load(t, "json.json").Get("wire").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			b := input(t, c)
			v, err := json.ReadToken(b64.Encode(b))
			if !answers(t, c, v, err) {
				return
			}
			w, err := json.Wire(v)
			if err != nil {
				t.Fatalf("Wire refused the value read: %v", err)
			}
			if !bytes.Equal(w, b) {
				t.Fatalf("Wire wrote other bytes than were read, from byte %d", firstDifference(w, b))
			}
		})
	})
}

// TestFile reads each file case as a file: steps 1 and 2, with the file limit.
func TestFile(t *testing.T) {
	vectors.Load(t, "json.json").Get("file").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			v, err := json.ReadFile(input(t, c))
			answers(t, c, v, err)
		})
	})
}

// TestFileFormat writes each case's value as a file, which gives its file text, and reads the text back,
// which gives the value. The text holds the members in canonical order, which a case's value need not.
func TestFileFormat(t *testing.T) {
	vectors.Load(t, "json.json").Get("fileFormat").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			want := c.Get("file").Str()
			got, err := json.File(build(c.Get("value")))
			if err != nil {
				t.Fatalf("File refused the value: %v", err)
			}
			if string(got) != want {
				t.Fatalf("File wrote\n%s\nwant\n%s", got, want)
			}
			v, err := json.ReadFile([]byte(want))
			if err != nil {
				t.Fatalf("ReadFile refused the file: %v", err)
			}
			if d := diff(v, c.Get("value"), false, "value"); d != "" {
				t.Fatal(d)
			}
		})
	})
}

// answers checks a read against case c's expected answer, member order included, and reports whether the
// case expects the read to succeed and it did.
func answers(t *testing.T, c vectors.Node, v json.Value, err error) bool {
	t.Helper()
	switch expected := c.Get("expected").Str(); expected {
	case "OK":
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if c.Has("value") {
			if d := diff(v, c.Get("value"), true, "value"); d != "" {
				t.Fatal(d)
			}
		}
		return true
	case "REFUSED":
		var e *json.Error
		if !errors.As(err, &e) {
			t.Fatalf("got %v, want a refusal at step %s", err, c.Get("step").Str())
		}
		if want := json.Step(c.Get("step").Str()); e.Step != want {
			t.Fatalf("refused at step %s (%v), want %s", e.Step, err, want)
		}
		return false
	default:
		t.Fatalf("expected is %q, not OK or REFUSED", expected)
		return false
	}
}

// input returns case c's bytes, from whichever of utf8, hex and build it gives.
func input(t testing.TB, c vectors.Node) []byte {
	t.Helper()
	switch {
	case c.Has("utf8"):
		return []byte(c.Get("utf8").Str())
	case c.Has("hex"):
		b, err := hex.DecodeString(c.Get("hex").Str())
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		return b
	case c.Has("build"):
		p := c.Get("build")
		times := int(p.Get("times").Int())
		return []byte(p.Get("head").Str() + strings.Repeat(p.Get("repeat").Str(), times) + p.Get("tail").Str())
	}
	t.Fatal("the case gives no utf8, hex or build input")
	return nil
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

// diff returns "" if got is the value vector node want describes, or where they first differ. With
// ordered, an object's members must also come in want's order.
func diff(got json.Value, want vectors.Node, ordered bool, path string) string {
	fail := func(format string, args ...any) string {
		return path + ": " + fmt.Sprintf(format, args...)
	}
	if k := kinds[want.Kind()]; got.Kind() != k {
		return fail("got %v, want %v", got.Kind(), k)
	}
	switch got.Kind() {
	case json.KindBool:
		if got.Bool() != want.Bool() {
			return fail("got %v, want %v", got.Bool(), want.Bool())
		}
	case json.KindInt:
		if got.Int() != want.Int() {
			return fail("got %v, want %v", got.Int(), want.Int())
		}
	case json.KindString:
		if got.Str() != want.Str() {
			return fail("got %+q, want %+q", got.Str(), want.Str())
		}
	case json.KindArray:
		items := got.Items()
		if len(items) != want.Len() {
			return fail("got %v items, want %v", len(items), want.Len())
		}
		for i, item := range items {
			if d := diff(item, want.Index(i), ordered, path+"["+strconv.Itoa(i)+"]"); d != "" {
				return d
			}
		}
	case json.KindObject:
		members := got.Members()
		names := want.Names()
		if len(members) != len(names) {
			return fail("got %v members, want %v", len(members), len(names))
		}
		for i, m := range members {
			if ordered && m.Name != names[i] {
				return fail("member %v is %+q, want %+q", i, m.Name, names[i])
			}
			if !want.Has(m.Name) {
				return fail("got the member %+q, which is not wanted", m.Name)
			}
			if d := diff(m.Value, want.Get(m.Name), ordered, path+"."+m.Name); d != "" {
				return d
			}
		}
	}
	return ""
}

// kinds maps the kind of a vector node to the kind of the Value it describes.
var kinds = map[vectors.Kind]json.Kind{
	vectors.Null: json.KindNull, vectors.Bool: json.KindBool, vectors.Number: json.KindInt,
	vectors.String: json.KindString, vectors.Array: json.KindArray, vectors.Object: json.KindObject,
}

// firstDifference returns the offset of the first byte at which a and b differ.
func firstDifference(a, b []byte) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}
