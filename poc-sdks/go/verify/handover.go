// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// StampItems is one stamp's entry in a hand-over: its signer, whether its block names the extension, and the
// items it holds under it, each the JCS text of one value (nil unless Named). Named is separate from Items
// because a block that names an extension with nothing to add differs from one that does not name it, and a
// block that only requires the extension is the second kind.
type StampItems struct {
	Svc   string
	Named bool
	Items []string
}

// HandOver is what a service is handed for the extensions it acts on (verification.md, The live order): for
// each, one StampItems per stamp in chain order. It cannot change once built.
type HandOver struct {
	verified bool
	byName   map[string][]StampItems
}

// NewHandOver returns, for each name ext acts on, one StampItems per stamp in chain order, and records
// whether the chain's signatures were verified. It panics if c and bs differ in length: a program fault,
// never a request's.
func NewHandOver(verified bool, c stamp.Chain, bs stamp.Blocks, ext Extensions) *HandOver {
	if len(c) != len(bs) {
		panic(fmt.Sprintf("paztport verify: a hand-over of %d stamps and %d blocks", len(c), len(bs)))
	}
	by := make(map[string][]StampItems, len(ext.actsOn))
	for _, name := range ext.actsOn {
		entries := make([]StampItems, len(c))
		for i, s := range c {
			items, named := bs[i].Items(name)
			entries[i] = StampItems{Svc: s.Svc, Named: named, Items: items}
		}
		by[name] = entries
	}
	return &HandOver{verified: verified, byName: by}
}

// Verified reports whether the chain's signatures were checked: false for a hand-over made without a key.
func (h *HandOver) Verified() bool {
	return h.verified
}

// Names returns the extensions the hand-over holds, sorted, as a copy.
func (h *HandOver) Names() []string {
	out := make([]string, 0, len(h.byName))
	for name := range h.byName {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Under returns a deep copy of the entries for name, one per stamp, and false when the service does not act
// on name.
func (h *HandOver) Under(name string) ([]StampItems, bool) {
	entries, ok := h.byName[name]
	if !ok {
		return nil, false
	}
	out := make([]StampItems, len(entries))
	for i, e := range entries {
		out[i] = StampItems{Svc: e.Svc, Named: e.Named, Items: slices.Clone(e.Items)}
	}
	return out, true
}
