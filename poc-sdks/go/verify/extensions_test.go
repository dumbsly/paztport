// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"reflect"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestZeroExtensions checks that the zero value acts on nothing and carries any name.
func TestZeroExtensions(t *testing.T) {
	var e verify.Extensions
	if len(e.ActsOn()) != 0 || e.ActsOnName("influence") || !e.Carries("anything") {
		t.Errorf("zero value: ActsOn %v, carries anything %v", e.ActsOn(), e.Carries("anything"))
	}
	if list, set := e.Allowed(); list != nil || set {
		t.Errorf("zero Allowed = %v, %v; want nil, false", list, set)
	}
}

// TestNewExtensionsCarriesAnyName checks the constructor that sets no list.
func TestNewExtensionsCarriesAnyName(t *testing.T) {
	e, err := verify.NewExtensions([]string{"influence"})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Carries("x") || !e.ActsOnName("influence") || e.ActsOnName("x") {
		t.Errorf("settings %+v", e)
	}
	if list, set := e.Allowed(); list != nil || set {
		t.Errorf("Allowed = %v, %v; want nil, false", list, set)
	}
	none, err := verify.NewExtensions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if list, set := none.Allowed(); list != nil || set {
		t.Errorf("NewExtensions(nil) Allowed = %v, %v; want nil, false", list, set)
	}
}

// TestNewExtensionsAllowing checks the constructor that sets a list, which may be empty.
func TestNewExtensionsAllowing(t *testing.T) {
	e, err := verify.NewExtensionsAllowing([]string{"a"}, []string{"b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Carries("c") || !e.Carries("a") || !e.Carries("b") {
		t.Errorf("Carries: c %v, a %v, b %v", e.Carries("c"), e.Carries("a"), e.Carries("b"))
	}
	if list, set := e.Allowed(); !reflect.DeepEqual(list, []string{"a", "b"}) || !set {
		t.Errorf("Allowed = %v, %v; want [a b], true", list, set)
	}

	empty, err := verify.NewExtensionsAllowing([]string{}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if empty.Carries("a") {
		t.Error("an empty list carries a name")
	}
	if list, set := empty.Allowed(); list == nil || len(list) != 0 || !set {
		t.Errorf("empty Allowed = %#v, %v; want an empty non-nil list, true", list, set)
	}
}

// TestExtensionsRefuse checks the three refusals.
func TestExtensionsRefuse(t *testing.T) {
	if e, err := verify.NewExtensionsAllowing([]string{"a"}, []string{"b"}); err == nil {
		t.Errorf("acts on a name outside allowed: %+v", e)
	}
	if e, err := verify.NewExtensions([]string{"Example"}); err == nil {
		t.Errorf("a name that is not an extension name: %+v", e)
	}
	if e, err := verify.NewExtensionsAllowing(nil, []string{"a_b"}); err == nil {
		t.Errorf("an allowed name that is not an extension name: %+v", e)
	}
}

// TestExtensionsHoldCopies checks that neither the caller's slices nor the slices handed out reach the settings.
func TestExtensionsHoldCopies(t *testing.T) {
	acts := []string{"a", "b"}
	allowed := []string{"a", "b", "c"}
	e, err := verify.NewExtensionsAllowing(acts, allowed)
	if err != nil {
		t.Fatal(err)
	}
	acts[0], allowed[2] = "z", "z"
	e.ActsOn()[0] = "z"
	list, _ := e.Allowed()
	list[0] = "z"
	if got := e.ActsOn(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("ActsOn = %v", got)
	}
	if list, _ := e.Allowed(); !reflect.DeepEqual(list, []string{"a", "b", "c"}) {
		t.Errorf("Allowed = %v", list)
	}
	if !e.Carries("c") || e.Carries("z") || !e.ActsOnName("a") || e.ActsOnName("z") {
		t.Error("the settings changed")
	}
}
