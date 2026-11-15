// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import "github.com/dumbsly/paztport/poc-sdks/go/stamp"

// Inbound is what a request being served carries on to the calls its handler makes: the chain it received and its
// blocks, one per stamp, which each call sends unchanged before the caller's own (wire.md, Blocks). The zero
// Inbound carries nothing: an origin's, or work outside any request. [Accepted.Inbound] and
// [PartnerAccepted.Inbound] give it for a request served with its chain.
type Inbound struct {
	// Chain is the chain received, nil for none.
	Chain stamp.Chain
	// Blocks are its blocks, one per stamp of Chain; nil with a Chain means every block is empty.
	Blocks stamp.Blocks
}
