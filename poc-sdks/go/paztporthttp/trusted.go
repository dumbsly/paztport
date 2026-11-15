// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"github.com/dumbsly/paztport/poc-sdks/go/influence"
)

// TrustedRecord reports whether the handler of the request a accepted may write a trusted record: a
// record later decisions take as fact, such as who holds a card. read is everything the handler has read
// since it started, such as the entries of its own calls' responses. It is false for every request: whether
// the chain was shaped only by trusted content is read from the items its stamps hand over, and no item is
// handed over yet.
func (a Accepted) TrustedRecord(read []influence.Entry) bool {
	return false // Plan 4b: the every-stamp rule over a verified hand-over, then the entries read.
}

// TrustedRecord reports whether the handler of the call p accepted may write a trusted record, read being
// everything the handler has read since it started. It is false for every call, as Accepted's is.
func (p PartnerAccepted) TrustedRecord(read []influence.Entry) bool {
	return false // Plan 4b: the every-stamp rule over the boundary block, then the entries read.
}
