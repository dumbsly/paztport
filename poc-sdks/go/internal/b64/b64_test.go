// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package b64_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
)

func TestVectors(t *testing.T) {
	vectors.Load(t, "json.json").Get("base64url").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			got, err := b64.Decode(c.Get("text").Str())
			if c.Get("expected").IsNull() {
				if err == nil {
					t.Fatalf("Decode accepted it as %x", got)
				}
				return
			}
			want, err2 := hex.DecodeString(c.Get("expected").Str())
			if err2 != nil {
				t.Fatalf("expected is not hex: %v", err2)
			}
			if err != nil {
				t.Fatalf("Decode refused it: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Decode = %x, want %x", got, want)
			}
		})
	})
}

// The standard library's decoder skips CR and LF, so these must be refused before it sees them.
func TestDecodeRefuses(t *testing.T) {
	for _, s := range []string{
		"AA\n",
		"AA\r",
		"AA\r\nAA",
		" AA",
		"AA ",
		"AB",
		"AC",
		"AE",
		"AI",
		"AAB",
		"AAC",
		"A",
		"AA==",
		"A+A",
		"A/A",
		"A\x00",
		"Aé",
	} {
		if got, err := b64.Decode(s); err == nil {
			t.Errorf("Decode(%q) = %x, want an error", s, got)
		}
	}
}

func TestDecodeNamesTheRule(t *testing.T) {
	for _, tc := range []struct{ s, rule string }{
		{"AA\n", "alphabet"},
		{"AA==", "alphabet"},
		{"AAAAA", "length"},
		{"AB", "unused bits"},
		{"AC", "unused bits"},
		{"AE", "unused bits"},
		{"AI", "unused bits"},
		{"AAB", "unused bits"},
		{"AAC", "unused bits"},
	} {
		_, err := b64.Decode(tc.s)
		if err == nil || !strings.Contains(err.Error(), tc.rule) {
			t.Errorf("Decode(%q) error = %v, want one naming the %s", tc.s, err, tc.rule)
		}
	}
}

// Each unused bit of a short group is checked, and no used bit is taken for one.
func TestDecodeKeepsTheUsedBits(t *testing.T) {
	for _, tc := range []struct{ s, want string }{
		{"AQ", "01"},
		{"AAE", "0001"},
	} {
		got, err := b64.Decode(tc.s)
		if err != nil {
			t.Errorf("Decode(%q): %v", tc.s, err)
			continue
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("Decode(%q) = %x, want %s", tc.s, got, tc.want)
		}
	}
}

func TestDecodeErrorDoesNotEchoInput(t *testing.T) {
	_, err := b64.Decode("secret!")
	if err == nil {
		t.Fatal("Decode accepted a character outside the alphabet")
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "!") {
		t.Fatalf("the error echoes its input: %v", err)
	}
}

func TestEncode(t *testing.T) {
	if got := b64.Encode([]byte{0xfb, 0xff, 0xbf}); got != "-_-_" {
		t.Fatalf("Encode(fbffbf) = %q, want the url-safe alphabet's -_-_", got)
	}
	b := make([]byte, 0, 64)
	for n := range 64 {
		s := b64.Encode(b)
		if strings.Contains(s, "=") {
			t.Fatalf("Encode of %d bytes is padded: %q", n, s)
		}
		got, err := b64.Decode(s)
		if err != nil {
			t.Fatalf("Decode(Encode(%d bytes)): %v", n, err)
		}
		if !bytes.Equal(got, b) {
			t.Fatalf("Decode(Encode(%x)) = %x", b, got)
		}
		b = append(b, byte(0xa5^n))
	}
}
