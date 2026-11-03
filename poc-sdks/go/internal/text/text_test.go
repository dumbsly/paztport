// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package text_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"", true},
		{"plain", true},
		{"\U0001F600", true},
		{"\xed\xa0\x80", false}, // U+D800, a surrogate, in the three bytes UTF-8 would give it
		{"\xed\xbf\xbf", false}, // U+DFFF
		{"\xc0\xaf", false},     // an overlong '/'
		{"\xf4\x90\x80\x80", false},
		{"cut \xe2\x82", false},
	} {
		if got := text.Valid(tc.s); got != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestIsNoncharacter(t *testing.T) {
	for _, tc := range []struct {
		r    rune
		want bool
	}{
		{0xFDCF, false},
		{0xFDD0, true},
		{0xFDEF, true},
		{0xFDF0, false},
		{0xFFFD, false},
		{0xFFFE, true},
		{0xFFFF, true},
		{0x1FFFE, true},
		{0x10FFFE, true},
		{0x10FFFF, true},
		{0x11FFFE, false}, // beyond U+10FFFF: not a code point at all
		{-2, false},
		{'a', false},
	} {
		if got := text.IsNoncharacter(tc.r); got != tc.want {
			t.Errorf("IsNoncharacter(%U) = %v, want %v", tc.r, got, tc.want)
		}
	}
}

func TestHasNoncharacter(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"", false},
		{"plain \uFFFD", false},
		{"a\uFFFEb", true},
		{"\uFDD0", true},
		{"end \U0010FFFF", true},
	} {
		if got := text.HasNoncharacter(tc.s); got != tc.want {
			t.Errorf("HasNoncharacter(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// TestTrimFileSpace trims JSON's four whitespace characters from either end of a key file's text, and
// nothing else: not a vertical tab, a form feed, a no-break space or a space inside the value.
func TestTrimFileSpace(t *testing.T) {
	nbsp := string(rune(0xA0))
	for _, tc := range []struct{ s, want string }{
		{"key", "key"},
		{" \t\r\nkey\n", "key"},
		{"\r\n\r\n", ""},
		{"a key", "a key"},
		{"\vkey\f", "\vkey\f"},
		{nbsp + "key" + nbsp, nbsp + "key" + nbsp},
	} {
		if got := text.TrimFileSpace(tc.s); got != tc.want {
			t.Errorf("TrimFileSpace(%q) = %q, want %q", tc.s, got, tc.want)
		}
	}
}
