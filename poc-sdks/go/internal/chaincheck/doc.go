// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package chaincheck holds the checks the live and the offline verifiers share, each written once: 3 to 6
// on the stamps, 8 and 9 on the last stamp, and 11 on the route. Checks 1 and 2 are the chain reader's
// (stamp.ReadChain). The verifiers choose the order and add their own checks around these: the policy
// window, freshness or the recorded times, replay and the peer.
//
// A verifier pins one or more keyrings and roots, each with its own window. It judges which are current
// once, at its own time, by [Current], and hands only those to checks 4 and 11: the keyrings as
// policy.Keyring values and the roots as [Root] values, since this package cannot name the verify
// package's types. [KeysFor] is check 4's lookup, which the event responder shares.
//
// Each check answers with a reason code, reason.OK when it holds, and never panics: a malformed proof or
// influence is a failed check, not an error.
package chaincheck
