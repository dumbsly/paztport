// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/session"
)

// requirement returns NewRequirement's requirement, failing the test on its error.
func requirement(t *testing.T, extensions []string, continueWithout bool) session.Requirement {
	t.Helper()
	r, err := session.NewRequirement(extensions, continueWithout)
	if err != nil {
		t.Fatalf("NewRequirement(%q, %t): %v", extensions, continueWithout, err)
	}
	return r
}

// TestCallsAfter pins what a client may do after each outcome of its check, with and without a requirement
// and its switch: only an attested reply listing every required name lets a client with a requirement make
// calls without the switch; with it, a call carries requires only for the names the reply listed, and none
// after any outcome but EXTENSION_REQUIRED and ATTESTED.
func TestCallsAfter(t *testing.T) {
	none := session.Requirement{}
	strict := requirement(t, []string{"influence", "example"}, false)
	loose := requirement(t, []string{"influence", "example"}, true)
	both := []string{"example", "influence"}
	tests := []struct {
		name   string
		need   session.Requirement
		check  session.Check
		listed []string
		want   session.Calls
	}{
		{"no requirement, no reply checked", none, "", nil, session.Calls{Calls: true, Requires: []string{}}},
		{"attested, listing both", strict, session.Attested, both, session.Calls{Calls: true, Requires: both}},
		{"unsafe, without the switch", strict, session.Unsafe, both, session.Calls{Requires: []string{}}},
		{"no reply checked, without the switch", strict, "", nil, session.Calls{Requires: []string{}}},
		{"one of two listed, without the switch", strict, session.ExtensionRequired, []string{"example"},
			session.Calls{Requires: []string{}}},
		{"one of two listed, with the switch", loose, session.ExtensionRequired, []string{"example"},
			session.Calls{Calls: true, Requires: []string{"example"}}},
		{"unsafe, with the switch", loose, session.Unsafe, both, session.Calls{Calls: true, Requires: []string{}}},
		{"a bad signature, with the switch", loose, session.BadSignature, nil,
			session.Calls{Calls: true, Requires: []string{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.need.CallsAfter(tt.check, tt.listed)
			if got.Calls != tt.want.Calls || !slices.Equal(got.Requires, tt.want.Requires) {
				t.Fatalf("CallsAfter = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestNewRequirement checks that a requirement holds each name once, sorted, refuses a name that is not an
// extension name, and hands out a copy that cannot change it.
func TestNewRequirement(t *testing.T) {
	r := requirement(t, []string{"influence", "example", "influence"}, true)
	if got := r.Extensions(); !slices.Equal(got, []string{"example", "influence"}) {
		t.Fatalf("Extensions = %q, want [example influence]", got)
	}
	if !r.ContinueWithout() {
		t.Fatal("ContinueWithout = false, for a requirement built with the switch")
	}
	r.Extensions()[0] = "changed"
	if got := r.Extensions(); got[0] != "example" {
		t.Fatalf("changing what Extensions returned changed the requirement: %q", got)
	}
	given := []string{"influence"}
	held := requirement(t, given, false)
	given[0] = "example"
	if got := held.Extensions(); !slices.Equal(got, []string{"influence"}) {
		t.Fatalf("changing the slice given changed the requirement: %q", got)
	}
	got := held.CallsAfter(session.Attested, []string{"influence"})
	got.Requires[0] = "changed"
	if again := held.CallsAfter(session.Attested, []string{"influence"}); again.Requires[0] != "influence" {
		t.Fatalf("changing what CallsAfter returned changed the requirement: %q", again.Requires)
	}

	var zero session.Requirement
	if got := zero.Extensions(); len(got) != 0 || zero.ContinueWithout() {
		t.Fatalf("the zero Requirement requires %q, switch %t", got, zero.ContinueWithout())
	}
	if empty := requirement(t, nil, false); len(empty.Extensions()) != 0 {
		t.Fatalf("a requirement of nothing requires %q", empty.Extensions())
	}

	for _, names := range [][]string{{"Influence"}, {""}, {"influence", "in fluence"}, {"a/b"}} {
		if _, err := session.NewRequirement(names, false); err == nil {
			t.Errorf("NewRequirement took %q", names)
		}
	}
}
