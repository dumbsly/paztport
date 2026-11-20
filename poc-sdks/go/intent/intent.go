// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package intent is the extension named intent (intent.md): facts the origin states about a request, which a
// service that requires them compares with the request it is sent. It is a set of functions over what the
// verifier hands on. The origin's item is read with [ParseItem]; a service reads what it is handed with
// [ReadRequest], and asks whether a verified hand-over holds the facts its handler requires with [Require].
//
// The package reads no request and compares nothing: which value a fact is compared with is the handler's to
// say, and a refusal of the comparison, INTENT_DENIED, is the handler's. The Go receiver in paztporthttp does not
// run these checks; a service that acts on intent calls them from its own code. Nor does the partner receiver
// refuse an intent item in a session, as intent.md has a partner do: a partner that acts on intent refuses any
// item under it itself and does not pass a session's hand-over to these functions.
package intent

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Name is the extension's name, under which its items travel in a block (intent.md).
const Name = "intent"

// Facts is what an intent item states: each fact's name with the JCS text of its value. The zero value holds none.
type Facts struct {
	byName map[string]string
}

// ParseItem reads one item handed on under intent, its JCS text, as the facts it states (intent.md, Facts and the
// item): an object with exactly one member, facts, an object of at least one member, each name an extension name
// and each value any value the wire reader takes. It refuses text that is not exactly the canonical text of one
// value. A service reports a request holding an item refused here as INTENT_MISMATCH (ReadRequest).
func ParseItem(item string) (Facts, error) {
	v, err := json.ReadWire([]byte(item))
	if err == nil {
		var f Facts
		if f, err = factsFromValue(v); err == nil {
			return f, nil
		}
	}
	return Facts{}, fmt.Errorf("paztport intent: malformed intent item: %w", err)
}

func factsFromValue(o json.Value) (Facts, error) {
	if err := json.Exactly(o, []string{"facts"}, nil); err != nil {
		return Facts{}, err
	}
	facts, _ := json.Field(o, "facts")
	if facts.Kind() != json.KindObject {
		return Facts{}, errors.New("facts is not an object")
	}
	members := facts.Members()
	if len(members) == 0 {
		return Facts{}, errors.New("facts is empty")
	}
	by := make(map[string]string, len(members))
	for _, m := range members {
		if !stamp.IsExtensionName(m.Name) {
			return Facts{}, fmt.Errorf("the fact name %q is not 1 to 32 of a-z, 0-9 and '-'", m.Name)
		}
		text, err := json.Wire(m.Value)
		if err != nil {
			return Facts{}, fmt.Errorf("the fact %q: %w", m.Name, err)
		}
		by[m.Name] = string(text)
	}
	return Facts{byName: by}, nil
}

// Names returns the names of the facts, sorted.
func (f Facts) Names() []string {
	return slices.Sorted(maps.Keys(f.byName))
}

// JSON returns the JCS text of the value of the fact called name, and false when the item states no such fact.
func (f Facts) JSON(name string) (string, bool) {
	text, ok := f.byName[name]
	return text, ok
}

// Request is what a request's hand-over holds under intent. It is built by ReadRequest, which alone records
// whether the items read: a Request built by hand reads, whatever its UnreadSigner holds.
type Request struct {
	// Facts is the origin's facts; none when the origin stated none or an item does not read.
	Facts Facts
	// UnreadSigner is the signer of the block holding an item that does not read, for the operator's log, since
	// the code names no one; "" when the items read. A stamp's svc may be "", so Reads, not this field, says
	// whether the items read.
	UnreadSigner string

	unread bool
}

// Reads reports whether the items handed on read.
func (r Request) Reads() bool {
	return !r.unread
}

// ReadRequest reads the items handed on under intent, one StampItems per stamp in chain order (check P1): the
// first stamp's block holds no item or one that ParseItem reads, and every later stamp's block holds none. Nil or
// empty stamps is nothing handed on, which reads, with no facts. A request that does not read is refused
// INTENT_MISMATCH, and its Request names the signer of the first block that failed.
func ReadRequest(stamps []verify.StampItems) Request {
	var facts Facts
	for i, s := range stamps {
		switch {
		case len(s.Items) == 0:
		case i == 0 && len(s.Items) == 1:
			f, err := ParseItem(s.Items[0])
			if err != nil {
				return Request{UnreadSigner: s.Svc, unread: true}
			}
			facts = f
		default:
			return Request{UnreadSigner: s.Svc, unread: true}
		}
	}
	return Request{Facts: facts}
}

// Require is check P2 for a handler that requires the facts named in needs: OK with needs empty, whatever h
// holds. Otherwise INTENT_MISSING for no hand-over, one that is not verified, or one from settings that do not act
// on intent; INTENT_MISMATCH when the items of a verified hand-over do not read; INTENT_MISSING when a name in needs
// is not among the facts; else OK. A fact is believed only from a verified hand-over, so nothing is read from an
// unverified one.
func Require(h *verify.HandOver, needs []string) reason.Code {
	if len(needs) == 0 {
		return reason.OK
	}
	if h == nil || !h.Verified() {
		return reason.IntentMissing
	}
	stamps, acted := h.Under(Name)
	if !acted {
		return reason.IntentMissing
	}
	r := ReadRequest(stamps)
	if !r.Reads() {
		return reason.IntentMismatch
	}
	for _, n := range needs {
		if _, ok := r.Facts.JSON(n); !ok {
			return reason.IntentMissing
		}
	}
	return reason.OK
}
