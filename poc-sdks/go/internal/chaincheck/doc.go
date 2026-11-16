// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package chaincheck holds the checks of verification.md's live order that the live and the offline verifiers
// share, each written once and numbered as the spec numbers them: 2 to 6 on the stamps ([Stamps]), 8 on the last
// stamp ([Binding]), 9a on the blocks ([Match]), which a service serving a request it did not verify also runs,
// 9a to 9c ([Blocks]), and 12 on the route ([Route]). Check 1 is the chain reader's (stamp.ReadChain). The
// verifiers choose the order and add their own checks around these: the policy window, freshness or the recorded
// times, the peer and replay.
//
// A verifier pins one or more keyrings and roots, each with its own window. It judges which are current
// once, at its own time, by [Current], and hands only those to checks 3 and 12: the keyrings as
// policy.Keyring values and the roots as [Root] values, since this package cannot name the verify
// package's types; for the same reason the extension settings reach [Blocks] as predicates. [KeysFor] is check
// 3's lookup, which the event responder shares.
//
// Each check answers with a reason code, reason.OK when it holds, and never panics: a malformed proof or
// blocks token is a failed check, not an error. No check reads an item: what an item means is its extension's to
// say, and this package imports none.
package chaincheck
