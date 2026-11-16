// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import "slices"

// PublicWriteRefused reports whether the owner-aware rule refuses a write, made under the influence es,
// to a public destination whose owner is destinationOwner. The write is refused when both hold:
//
//   - es holds untrusted content: a ThirdParty or LocalUntrusted entry; and
//   - es holds private data that is not the destination owner's: a Private entry with no owner or
//     another owner, or any Private entry when destinationOwner is "", which is unknown.
//
// An unknown owner, on either side, fails closed: it counts as someone else's. So untrusted content can
// steer a write of a customer's own data to that customer, but never someone else's data, or data whose
// owner nobody knows.
//
// The caller takes destinationOwner from its own trusted records, such as the authenticated account the
// write is for or the stored owner of the target, never from the request's arguments, the content or the
// influence: those are what an attacker writes. A write to a destination that is not public is not this
// rule's to decide.
//
// Only the entries' classes and owners count. A class other than the four, which only an Entry built by
// hand can hold, fails closed too: it counts as untrusted content and as private data of an unknown
// owner.
func PublicWriteRefused(es []Entry, destinationOwner string) bool {
	untrusted := slices.ContainsFunc(es, func(e Entry) bool { return e.Class.untrusted() })
	foreign := slices.ContainsFunc(es, func(e Entry) bool {
		return !e.Class.known() || (e.Class == Private && (e.Owner == "" || e.Owner != destinationOwner))
	})
	return untrusted && foreign
}

// GuardedWriteRefused reports whether a guarded public write is refused (influence.md, The every-stamp rule, then
// The owner-aware rule): always when a stamp of the chain does not name influence, since that hop may have read
// anything, the model's host included, whatever the entries say; otherwise as PublicWriteRefused decides over es,
// everything the request holds, the entries handed on and those the service added. everyStampNames is true where
// there is no stamp to read, since the rule cannot refuse for what it is not shown (What the rules read).
func GuardedWriteRefused(everyStampNames bool, es []Entry, destinationOwner string) bool {
	return !everyStampNames || PublicWriteRefused(es, destinationOwner)
}

// ShapedOnlyByTrusted reports whether a service may write a trusted record from a request (influence.md, Trusted
// records): a record that later decisions take as fact, such as who holds a card, which PublicWriteRefused then
// reads as a destination's owner. That rule can't judge such a write, since it asks whose private data a write
// carries, and a record written because untrusted text asked for it carries none. So a record may be written only
// when all hold:
//
//   - verified: the request's chain passed the live order at this hop, so each block's items are the ones its
//     stamp's signer committed to. An origin, a service with no verifier, a hop on which Paztport is off, a
//     request served unverified, a call in an unsafe partner session and work outside any request never
//     qualify;
//   - everyStampNames: every stamp of that chain names influence, so no hop on the path is one that may have
//     read anything; and
//   - es holds no untrusted content: no ThirdParty and no LocalUntrusted entry.
//
// es is the influence the request holds when the record is written: the entries handed on, and everything the
// service has read since, such as the responses to its own calls. Private and public entries, and owners, count
// neither way: they say whose data the request read, not who steered it. A class other than the four fails
// closed, as untrusted content. A request that fails the rule may still be served, but the record must not be
// written from it.
func ShapedOnlyByTrusted(verified, everyStampNames bool, es []Entry) bool {
	return verified && everyStampNames && !slices.ContainsFunc(es, func(e Entry) bool { return e.Class.untrusted() })
}
