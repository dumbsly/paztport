// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// EncodeChain returns the value of a request's [Chain] header: c's token. It refuses what
// stamp.Chain.Token refuses, an empty chain among them.
func EncodeChain(c stamp.Chain) (string, error) {
	return c.Token()
}

// EncodeProof returns the value of a request's [Proof] header: p's token. It refuses what
// policy.Proof.Token refuses.
func EncodeProof(p policy.Proof) (string, error) {
	return p.Token()
}

// EncodeBlocks returns the value of a request's [Extensions] header: the token of bs, the blocks one per stamp
// of the chain it travels with, in chain order. It is always a token, never "", so a sender sends the header
// whatever its blocks hold. It refuses blocks whose wire bytes would pass the wire limit, 256 KiB: nothing is
// dropped to make room.
func EncodeBlocks(bs stamp.Blocks) (string, error) {
	tok, err := bs.Token()
	if err != nil {
		return "", fmt.Errorf("paztport wire: the blocks header can't be written: %w", err)
	}
	return tok, nil
}

// EncodeResponse returns the value of a response's [Response] header: the token of the object {block, stamp},
// with exactly those members, s the response stamp and block the block its ext commits to. It refuses a stamp
// that stamp.Stamp.Wire refuses and an object over the wire limit.
func EncodeResponse(s stamp.Stamp, block stamp.Block) (string, error) {
	unwritable := func(err error) error {
		return fmt.Errorf("paztport wire: the response header can't be written: %w", err)
	}
	sb, err := s.Wire()
	if err != nil {
		return "", err
	}
	sv, err := json.ReadWire(sb)
	if err != nil {
		return "", unwritable(err)
	}
	bv, err := json.ReadWire(block.Wire())
	if err != nil {
		return "", unwritable(err)
	}
	tok, err := json.Token(json.Obj(
		json.Member{Name: "block", Value: bv},
		json.Member{Name: "stamp", Value: sv},
	))
	if err != nil {
		return "", unwritable(err)
	}
	return tok, nil
}
