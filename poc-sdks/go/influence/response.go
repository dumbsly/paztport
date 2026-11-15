// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// ResponseBlock is a response's block for a responder that acts on influence: it names influence with labels, each
// as its canonical text, in the order given, and with [] when there is none, since such a responder names it on
// every response it attests. When there is a label, requires holds influence, added here if left out, so a caller
// that does not act on influence refuses the response at check 9c instead of dropping the labels (influence.md,
// Content labels). It refuses a label LabelsWire refuses, and what stamp.NewBlock refuses of requires.
func ResponseBlock(labels []Label, requires []string) (stamp.Block, error) {
	items, err := texts("label", labels)
	if err != nil {
		return stamp.Block{}, err
	}
	required := slices.Clone(requires)
	if len(labels) > 0 && !slices.Contains(required, Name) {
		required = append(required, Name)
	}
	return stamp.NewBlock(map[string][]string{Name: items}, required)
}

// ResponseEntries are the entries a caller that acts on influence adds for one response over HTTP (influence.md,
// Content labels). code is the response check's result, "" where none ran; response is the response stamp's own
// StampItems under influence, nil where there is none. Over HTTP the response has one block, so only that stamp's
// is read.
//
// When code is OK and the block names influence with only labels, the response adds one entry per label, in their
// order, by Label.Entry; a block naming influence with no label adds none. Otherwise it adds exactly one
// local-untrusted entry, never dropped: a label counts only when the whole response verifies, and a response that
// is silent, holds an item that is not a label, failed its check or was checked by none is one the caller cannot
// vouch for. src is http:<target>, the caller's name for the service it sent the request to, and resultHash the
// response's result hash: every entry's src and h.
func ResponseEntries(code reason.Code, response *verify.StampItems, src, resultHash string) []Entry {
	untrusted := []Entry{{Class: LocalUntrusted, Src: src, H: resultHash}}
	if code != reason.OK || response == nil || !response.Named {
		return untrusted
	}
	entries := make([]Entry, 0, len(response.Items))
	for _, item := range response.Items {
		l, err := ParseLabel(item)
		if err != nil {
			return untrusted
		}
		entries = append(entries, l.Entry(src, resultHash))
	}
	return entries
}
