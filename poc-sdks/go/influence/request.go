// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"fmt"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Name is the extension's name, under which its items travel in a block (influence.md).
const Name = "influence"

// RequestBlock is a request's block for a hop that acts on influence: it names influence with entries, each as its
// canonical text, in the order given, and requires requires. With no entries it names influence with [], so it is
// not the empty block: a service that acts on influence names it in every block it signs (influence.md, The
// every-stamp rule). entries are what the hop added itself for this request so far, never those it received, which
// travel on in their own blocks. It refuses an entry EntriesWire refuses, and what stamp.NewBlock refuses of
// requires.
func RequestBlock(entries []Entry, requires []string) (stamp.Block, error) {
	items, err := texts("entry", entries)
	if err != nil {
		return stamp.Block{}, err
	}
	return stamp.NewBlock(map[string][]string{Name: items}, requires)
}

// texts returns each of xs's canonical text, as a block holds an item, naming what an x is in a refusal.
func texts[T interface{ value() (json.Value, error) }](what string, xs []T) ([]string, error) {
	out := make([]string, len(xs))
	for i, x := range xs {
		v, err := x.value()
		if err == nil {
			var b []byte
			if b, err = json.Wire(v); err == nil {
				out[i] = string(b)
				continue
			}
		}
		return nil, fmt.Errorf("paztport influence: %s %d can't be written: %w", what, i, err)
	}
	return out, nil
}

// Request is what a request's hand-over holds under influence (influence.md, The every-stamp rule and Entries).
// It is built by ReadRequest, which alone records whether every item read: a Request built by hand reports
// Reads true, whatever its UnreadSigner holds. What the service adds itself is the caller's to add.
type Request struct {
	// Entries is every item of every block, read as an entry, in chain order; none when an item does not read.
	Entries []Entry
	// EveryStampNames reports whether every stamp's block names influence. It is true where nothing was handed
	// on, since the rule cannot refuse for what it is not shown (What the rules read), and false when an item
	// does not read, since no rule is reached then.
	EveryStampNames bool
	// UnreadSigner is the signer of the first block holding an item that does not read, for the operator's log,
	// since the code names no one; "" when every item reads. A chain's reading allows a stamp whose svc is "", so
	// Reads, not this field, says whether every item read.
	UnreadSigner string

	refusal reason.Code // INFLUENCE_MISMATCH when an item does not read; "" when every item reads
}

// Reads reports whether every item handed on reads as an entry.
func (r Request) Reads() bool {
	return r.refusal == ""
}

// ReadRequest reads the items handed on under influence, one StampItems per stamp in chain order: every item of
// every block, in order, each read as an entry by ParseEntry. A stamp whose block does not name influence, Named
// false, means not every stamp names it, and a block that only requires influence is one. Nil or empty is nothing
// handed on: there is no stamp to read, so every stamp names it, and there are no entries.
//
// A request holding an item that does not read is refused INFLUENCE_MISMATCH (influence.md, Entries): this is the
// one place that code is given for it, and Decide and Items take it from here.
func ReadRequest(stamps []verify.StampItems) Request {
	var entries []Entry
	every := true
	for _, s := range stamps {
		if !s.Named {
			every = false
			continue
		}
		for _, item := range s.Items {
			e, err := ParseEntry(item)
			if err != nil {
				return Request{UnreadSigner: s.Svc, refusal: reason.InfluenceMismatch}
			}
			entries = append(entries, e)
		}
	}
	return Request{Entries: entries, EveryStampNames: every}
}

// Decision is what a service that acts on influence decides for a request (influence.md, What the rules read).
type Decision struct {
	// Reason is OK, INFLUENCE_DENIED or INFLUENCE_MISMATCH. The last two name no one.
	Reason reason.Code
	// EveryStampNames reports whether every stamp handed on names influence; false when Reason is
	// INFLUENCE_MISMATCH, since no rule was reached.
	EveryStampNames bool
	// UnreadSigner is, when Reason is INFLUENCE_MISMATCH, the signer of the first block holding an item that does
	// not read, for the operator's log; else "".
	UnreadSigner string
}

// Decide is what a service that acts on influence decides for a request (influence.md, What the rules read):
// INFLUENCE_MISMATCH when an item handed on does not read, for a write and a read alike and before either rule;
// else, for a guarded public write, INFLUENCE_DENIED when GuardedWriteRefused refuses it over the entries handed
// on plus added; else OK.
//
// stamps is what the verifier handed on under influence, as ReadRequest takes it; added is what the service added
// itself, the responses to its own calls among them; guardedWrite is whether the request writes to a public
// destination; destinationOwner is that destination's owner, from the service's own trusted records, "" when
// unknown.
func Decide(stamps []verify.StampItems, added []Entry, guardedWrite bool, destinationOwner string) Decision {
	r := ReadRequest(stamps)
	if !r.Reads() {
		return Decision{Reason: r.refusal, UnreadSigner: r.UnreadSigner}
	}
	if guardedWrite && GuardedWriteRefused(r.EveryStampNames, slices.Concat(r.Entries, added), destinationOwner) {
		return Decision{Reason: reason.InfluenceDenied, EveryStampNames: r.EveryStampNames}
	}
	return Decision{Reason: reason.OK, EveryStampNames: r.EveryStampNames}
}

// Items is influence's offline item check, an offline.ItemCheck (verification.md, Offline verification):
// INFLUENCE_MISMATCH when an item handed on under influence does not read, else OK.
//
// It panics when h comes from settings that do not act on influence: such a hand-over holds nothing under it, so
// every call would pass unread. That is the verifier's configuration, never a request's, so it is a program fault,
// as a verifier with no clock is. A nil hand-over, which RecordSet.Call never passes since it calls an item check
// only on OK, hands nothing on and gives OK.
func Items(h *verify.HandOver) reason.Code {
	if h == nil {
		return reason.OK
	}
	stamps, acted := h.Under(Name)
	if !acted {
		panic("paztport influence: Items needs a hand-over from settings that act on influence; " +
			"the offline verifier's settings must act on influence to read its items")
	}
	if r := ReadRequest(stamps); !r.Reads() {
		return r.refusal
	}
	return reason.OK
}
