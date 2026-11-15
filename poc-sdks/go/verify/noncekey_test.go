// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestNonceKey pins the key's text: the JCS array of the parts, a noncharacter written as itself.
func TestNonceKey(t *testing.T) {
	for _, c := range []struct {
		name  string
		parts []string
		want  string
	}{
		{"a call's parts", []string{"rid-1", "orders", "payment#charge", "req"}, `["rid-1","orders","payment#charge","req"]`},
		{"escapes", []string{"a\"b", "c|d", "\n"}, `["a\"b","c|d","\n"]`},
		{"a noncharacter", []string{"call-\uFFFF"}, "[\"call-\uFFFF\"]"},
		{"no parts", nil, "[]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, err := verify.NonceKey(c.parts...); err != nil || got != c.want {
				t.Errorf("NonceKey = %+q, %v; want %+q", got, err, c.want)
			}
		})
	}
}

// TestNonceKeyRefusesInvalidUTF8 checks that text with no UTF-8 reading has no key.
func TestNonceKeyRefusesInvalidUTF8(t *testing.T) {
	for _, bad := range []string{"a\xff", "\xed\xa0\x80"} {
		if got, err := verify.NonceKey("ok", bad); err == nil {
			t.Errorf("NonceKey(%+q) = %q, want an error", bad, got)
		}
	}
}

// TestNonceKeyPartsDoNotRunTogether checks that two parts never make the key of one part holding a comma.
func TestNonceKeyPartsDoNotRunTogether(t *testing.T) {
	two, err := verify.NonceKey("a", "b")
	if err != nil {
		t.Fatal(err)
	}
	one, err := verify.NonceKey("a\",\"b")
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Errorf("one part and two parts both give %q", one)
	}
}
