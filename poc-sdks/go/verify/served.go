// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"github.com/dumbsly/paztport/poc-sdks/go/internal/chaincheck"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// ServedUnverified is what a service does with the blocks of a request it is about to serve without having
// verified it: in audit mode after a failure, with no verifier, where it runs the live order only to attest, or
// with Paztport off (verification.md, "A service never serves a request whose blocks fail check 9a" and "What a
// request served without verifying is handed"). It needs no key, so it is a function, not a Verifier method.
//
// chain and blocks are the tokens received, nil for none. Where the chain reads, all of check 9a applies. Where
// it does not, or none came, there are no stamps to match the blocks to, so they must still read as an array of
// blocks (none received reads). Checks 9b and 9c are not applied: they follow the mode, and a caller that ran
// the verifier already has its result for them.
//
// serve false means the request is not served (over HTTP, 400 EXTENSION_MISMATCH). h holds the items handed
// on, not verified, only for the extensions ext acts on; it is nil when serve is false and when the chain did
// not read.
func ServedUnverified(chain, blocks *string, ext Extensions) (h *HandOver, serve bool) {
	if chain != nil {
		if c, code := stamp.ReadChain(*chain); code == reason.OK {
			bs, code := chaincheck.Match(c, blocks)
			if code != reason.OK {
				return nil, false
			}
			return NewHandOver(false, c, bs, ext), true
		}
	}
	if blocks != nil {
		if _, err := stamp.ReadBlocks(*blocks); err != nil {
			return nil, false
		}
	}
	return nil, true
}
