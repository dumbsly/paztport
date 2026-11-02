// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
)

// TrustedRecord reports whether the handler of the request a accepted may write a trusted record: a
// record later decisions take as fact, such as who holds a card. read is everything the handler has
// read since it started, such as the entries of its own calls' responses. It is
// [influence.ShapedOnlyByTrusted] over a's verdict and a's influence followed by read: the chain must
// have passed the live order at this hop, and neither the influence it came with nor anything read since
// may hold third-party or local-untrusted content.
//
// A refusal, an origin, a hop that is off, a service with no verifier and a chain that failed in audit
// mode never qualify, and nor does the zero Accepted, which stands for work outside any request.
func TrustedRecord(a Accepted, read []influence.Entry) bool {
	return influence.ShapedOnlyByTrusted(a.Verified, slices.Concat(a.Influence, read))
}
