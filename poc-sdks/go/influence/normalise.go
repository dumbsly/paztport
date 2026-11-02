// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"cmp"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// Normalise returns a sorted copy of es with exact duplicates removed. It sorts by H, then Class, then
// Src, then CID, then Owner, comparing text by its UTF-16 code units, the order JCS sorts member names
// in; an absent cid or owner sorts before any present one. Two entries are duplicates when their wire
// forms are equal, so an entry with an owner and the same entry without one are both kept.
//
// Normalising first means the order a client happened to record things in doesn't change the
// commitment.
func Normalise(es []Entry) []Entry {
	sorted := slices.Clone(es)
	slices.SortStableFunc(sorted, compare)
	return slices.CompactFunc(sorted, func(a, b Entry) bool { return compare(a, b) == 0 })
}

// Commit returns the commitment to es that a stamp carries as infl: "" when es is empty, and otherwise
// b64url(SHA-256(JCS(Normalise(es)))). It refuses what EntriesWire refuses.
func Commit(es []Entry) (string, error) {
	if len(es) == 0 {
		return "", nil
	}
	b, err := EntriesWire(Normalise(es))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return b64.Encode(sum[:]), nil
}

// compare orders a and b as Normalise sorts them. It returns 0 exactly when their wire forms are equal:
// a CID is compared only when HasCID is set, as only then is it written.
func compare(a, b Entry) int {
	return cmp.Or(
		compareText(a.H, b.H),
		compareText(string(a.Class), string(b.Class)),
		compareText(a.Src, b.Src),
		compareOptional(a.HasCID, a.CID, b.HasCID, b.CID),
		compareOptional(a.Owner != "", a.Owner, b.Owner != "", b.Owner),
	)
}

// compareOptional orders two optional texts, an absent one first.
func compareOptional(hasA bool, a string, hasB bool, b string) int {
	switch {
	case hasA && hasB:
		return compareText(a, b)
	case hasA:
		return 1
	case hasB:
		return -1
	}
	return 0
}

// compareText orders a and b by their UTF-16 code units. LessUTF16 reads a byte that is not valid UTF-8
// as U+FFFD, so two different such strings can tie there; their bytes then decide, so that the order is
// total and Normalise gives one answer for any input. No such text is ever written or committed.
func compareText(a, b string) int {
	switch {
	case json.LessUTF16(a, b):
		return -1
	case json.LessUTF16(b, a):
		return 1
	}
	return strings.Compare(a, b)
}
