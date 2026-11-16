// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// PublicWrite decides a guarded public write to a destination owned by destinationOwner ("" for none) from this
// request (influence.md, What the rules read): reason.OK or reason.InfluenceDenied, never another code (The
// owner-aware rule). read is what the service added for the request since it was accepted, such as the entries of
// its own calls' responses. destinationOwner comes from the service's own trusted records, never from the request,
// or the request could name its own.
//
// It reads what the request was handed, verified or not: a stamp handed on that does not name influence denies
// the write whatever the entries say (The every-stamp rule), and otherwise the owner-aware rule decides over the
// entries handed on plus read. Where nothing was handed on, at an origin, where the chain did not read or none
// came, there is no stamp to read, and the owner-aware rule decides over read alone.
//
// At a service whose settings do not act on influence it is always InfluenceDenied: the rules are those of a
// service that acts on influence, and a write-guarding service deployed without the extension is the mistake they
// exist to catch. A refused request, and the zero Accepted, which has no settings, are denied too.
func (a Accepted) PublicWrite(read []influence.Entry, destinationOwner string) reason.Code {
	return publicWrite(a.Refusal != nil, a.ext, a.HandOver, read, destinationOwner)
}

// TrustedRecord reports whether a trusted record may be written from this request (influence.md, Trusted records):
// a record later decisions take as fact, such as who holds a card. It needs a verified hand-over, every stamp
// naming influence, and no untrusted entry in what was handed on plus read (everything the service read since it
// accepted the request). So it is false for a request served unverified, at an origin, where nothing was handed on,
// for a refusal and for the zero Accepted. False at a service whose settings do not act on influence.
func (a Accepted) TrustedRecord(read []influence.Entry) bool {
	return trustedRecord(a.Refusal != nil, a.ext, a.HandOver, read)
}

// PublicWrite decides a guarded public write from the call p accepted, as [Accepted.PublicWrite] does from a
// request, over the boundary stamp's block and read (influence.md, Blinded influence: at the partner, the
// every-stamp rule reads the one boundary stamp). In an unsafe session nothing is handed on, so it decides over
// read alone: a partner keeps its public writes from such calls by switching them off ([UnsafeEndpoints]).
func (p PartnerAccepted) PublicWrite(read []influence.Entry, destinationOwner string) reason.Code {
	return publicWrite(p.Refusal != nil, p.ext, p.HandOver, read, destinationOwner)
}

// TrustedRecord reports whether a trusted record may be written from the call p accepted, as
// [Accepted.TrustedRecord] does for a request: only for an Attested call whose boundary block names influence,
// with no untrusted entry in it or in read. Never in an unsafe session.
func (p PartnerAccepted) TrustedRecord(read []influence.Entry) bool {
	return trustedRecord(p.Refusal != nil, p.ext, p.HandOver, read)
}

// influenceStamps returns what h hands on under influence for a service with settings ext, and true where the
// rules may decide: not for a refusal, nor where ext does not act on influence. A nil h hands on nothing, no
// stamp. An h that holds nothing under influence beside settings acting on it was not built under them, such as
// one an embedder set by hand, and is refused rather than read as nothing handed on.
func influenceStamps(refused bool, ext verify.Extensions, h *verify.HandOver) ([]verify.StampItems, bool) {
	if refused || !ext.ActsOnName(influence.Name) {
		return nil, false
	}
	if h == nil {
		return nil, true
	}
	return h.Under(influence.Name)
}

// publicWrite is PublicWrite for a request or a call: refused, its settings ext and its hand-over h.
func publicWrite(
	refused bool, ext verify.Extensions, h *verify.HandOver, read []influence.Entry, destinationOwner string,
) reason.Code {
	stamps, ok := influenceStamps(refused, ext, h)
	if !ok {
		return reason.InfluenceDenied
	}
	// Decide gives INFLUENCE_MISMATCH where an item handed on does not read. Accept refused such a request at a
	// service acting on influence, so only a hand-over set by hand can reach it here, and it is denied.
	if influence.Decide(stamps, read, true, destinationOwner).Reason != reason.OK {
		return reason.InfluenceDenied
	}
	return reason.OK
}

// trustedRecord is TrustedRecord for a request or a call: refused, its settings ext and its hand-over h.
func trustedRecord(refused bool, ext verify.Extensions, h *verify.HandOver, read []influence.Entry) bool {
	stamps, ok := influenceStamps(refused, ext, h)
	if !ok || h == nil {
		return false
	}
	// EveryStampNames is false where an item handed on does not read, so such a hand-over writes no record.
	r := influence.ReadRequest(stamps)
	return influence.ShapedOnlyByTrusted(h.Verified(), r.EveryStampNames, slices.Concat(r.Entries, read))
}
