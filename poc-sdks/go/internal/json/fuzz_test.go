// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json_test

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
)

// FuzzReadToken reads any text as a token. A read never panics and refuses only with an *Error, and a
// value it reads writes back as the same token, since a token's bytes are canonical.
func FuzzReadToken(f *testing.F) {
	for _, b := range seeds(f) {
		f.Add(b64.Encode(b))
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := json.ReadToken(s)
		if err != nil {
			refusal(t, err)
			return
		}
		back, err := json.Token(v)
		if err != nil {
			t.Fatalf("Token refused a value ReadToken read: %v", err)
		}
		if back != s {
			t.Fatal("Token wrote another token than ReadToken read")
		}
	})
}

// FuzzReadFile reads any bytes as a file. A read never panics and refuses only with an *Error, and a value
// it reads has canonical bytes, unless they are over the wire limit, and a file form, unless that is over
// the file limit; each reads back as the same value.
func FuzzReadFile(f *testing.F) {
	for _, b := range seeds(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := json.ReadFile(b)
		if err != nil {
			refusal(t, err)
			return
		}
		// The canonical bytes are never longer than the text read, which has whitespace and escapes where
		// they have none.
		wire, err := json.Wire(v)
		if err != nil {
			if len(b) <= json.WireBytes || !sizeRefusal(err, "the wire bytes would be over the "+strconv.Itoa(json.WireBytes)+"-byte limit") {
				t.Fatalf("Wire refused a value ReadFile read from %d bytes: %v", len(b), err)
			}
			return
		}
		back, err := json.ReadWire(wire)
		if err != nil {
			t.Fatalf("ReadWire refused the bytes Wire wrote: %v", err)
		}
		if again, _ := json.Wire(back); !bytes.Equal(again, wire) {
			t.Fatal("the canonical bytes read back as another value")
		}
		file, err := json.File(v)
		if err != nil {
			if !sizeRefusal(err, "the file would be over the "+strconv.Itoa(json.FileBytes)+"-byte limit") {
				t.Fatalf("File refused a value ReadFile read: %v", err)
			}
			return
		}
		back, err = json.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile refused the file File wrote: %v", err)
		}
		if again, _ := json.Wire(back); !bytes.Equal(again, wire) {
			t.Fatal("the file read back as another value")
		}
	})
}

// seeds returns every input in json.json's wire, file and fileFormat sections.
func seeds(f *testing.F) [][]byte {
	file := vectors.Load(f, "json.json")
	var out [][]byte
	for _, section := range []string{"wire", "file"} {
		file.Get(section).Each(func(_ string, c vectors.Node) { out = append(out, input(f, c)) })
	}
	file.Get("fileFormat").Each(func(_ string, c vectors.Node) { out = append(out, []byte(c.Get("file").Str())) })
	return out
}

// sizeRefusal reports whether err is a writer's refusal for rule, the rule of its size limit.
func sizeRefusal(err error, rule string) bool {
	return step(err) == json.StepWrite && strings.HasSuffix(err.Error(), ": "+rule)
}

// refusal fails t unless err is an *Error.
func refusal(t *testing.T, err error) {
	t.Helper()
	var e *json.Error
	if !errors.As(err, &e) {
		t.Fatalf("refused with %T, not *json.Error: %v", err, err)
	}
}
