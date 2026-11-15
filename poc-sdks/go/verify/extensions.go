// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Extensions is a service's extension settings (verification.md, Inputs): the extensions it acts on, and the
// names its verifier carries. The zero value acts on none and carries any name. It is built by a constructor,
// so a verifier never meets settings that break the rule that a service cannot act on an extension its own
// list refuses, and it holds copies, so the caller's slices cannot change it.
type Extensions struct {
	actsOn  []string // sorted, none twice
	allowed []string // sorted, none twice; meaningful only when listed
	listed  bool     // false: any name is carried; true: only allowed, which may be empty
}

// NewExtensions returns settings that act on actsOn and carry any name. It refuses a name that is not an
// extension name.
func NewExtensions(actsOn []string) (Extensions, error) {
	acts, err := names("actsOn", actsOn)
	if err != nil {
		return Extensions{}, err
	}
	return Extensions{actsOn: acts}, nil
}

// NewExtensionsAllowing returns settings that act on actsOn and carry only the names in allowed, which may be
// empty: a service that carries no extension at all, as distinct from NewExtensions, which carries any. It
// refuses a name that is not an extension name and an actsOn name outside allowed.
func NewExtensionsAllowing(actsOn, allowed []string) (Extensions, error) {
	acts, err := names("actsOn", actsOn)
	if err != nil {
		return Extensions{}, err
	}
	carried, err := names("allowed", allowed)
	if err != nil {
		return Extensions{}, err
	}
	for _, name := range acts {
		if _, found := slices.BinarySearch(carried, name); !found {
			return Extensions{}, fmt.Errorf("paztport verify: extension settings act on %q, which allowed does not hold", name)
		}
	}
	return Extensions{actsOn: acts, allowed: carried, listed: true}, nil
}

// names returns a sorted copy of list without repeats, refusing a name that is not an extension name. Names
// are ASCII, so byte order is UTF-16 code unit order.
func names(what string, list []string) ([]string, error) {
	out := slices.Clone(list)
	slices.Sort(out)
	out = slices.Compact(out)
	for _, name := range out {
		if !stamp.IsExtensionName(name) {
			return nil, fmt.Errorf("paztport verify: extension settings %s: %q is not an extension name", what, name)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// ActsOn returns the extensions the service acts on, sorted, as a copy.
func (e Extensions) ActsOn() []string {
	return slices.Clone(e.actsOn)
}

// ActsOnName reports whether the service acts on the extension name.
func (e Extensions) ActsOnName(name string) bool {
	_, found := slices.BinarySearch(e.actsOn, name)
	return found
}

// Allowed returns the names the verifier carries, sorted, as a copy, and whether a list is set. When none is
// set the verifier carries any name and the slice is nil; a set list may be empty.
func (e Extensions) Allowed() ([]string, bool) {
	if !e.listed {
		return nil, false
	}
	return slices.Clone(e.allowed), true
}

// Carries reports whether the verifier carries the extension name: true when no list is set or it holds name.
func (e Extensions) Carries(name string) bool {
	if !e.listed {
		return true
	}
	_, found := slices.BinarySearch(e.allowed, name)
	return found
}
