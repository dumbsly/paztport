// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package chaincheck holds the checks the live and the offline verifiers share, each written once: 3 to 6
// on the stamps, 8 and 9 on the last stamp, and 11 on the route. Checks 1 and 2 are the chain reader's
// (stamp.ReadChain). The verifiers choose the order and add their own checks around these: the policy
// window, freshness or the recorded times, replay and the peer.
//
// Each check answers with a reason code, reason.OK when it holds, and never panics: a malformed proof or
// influence is a failed check, not an error.
package chaincheck
