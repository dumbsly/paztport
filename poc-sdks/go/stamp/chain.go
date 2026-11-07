// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
)

// Chain is the stamps of one request, origin first. On the wire it is a JSON array of the stamps.
type Chain []Stamp

// RouteOf returns the route a chain takes: the first stamp's svc, then each stamp's rcv, so an operation a hop
// names is part of the route. With inRoute false the last rcv is left off. It is the route that a policy's
// leaf, a verifier and a caller's proof lookup all build, joined by [policy.JoinRoute].
func RouteOf(c Chain, inRoute bool) string {
	if len(c) == 0 {
		return ""
	}
	nodes := make([]string, 0, len(c)+1)
	nodes = append(nodes, c[0].Svc)
	for _, s := range c {
		nodes = append(nodes, s.Rcv)
	}
	if !inRoute {
		nodes = nodes[:len(nodes)-1]
	}
	return policy.JoinRoute(nodes...)
}

// stampMembers are a stamp's member names: every one is required, and no other is allowed.
var stampMembers = []string{"bind", "infl", "inst", "prev", "rcv", "rid", "sess", "sig", "svc", "ts", "v"}

// ReadChain reads a chain from its token, the base64url of its wire bytes, as ParseChain reads the bytes.
// A token that is not canonical base64url, or is over the token limit, is CHAIN_MISSING.
func ReadChain(tok string) (Chain, reason.Code) {
	v, err := json.ReadToken(tok)
	if err != nil {
		return nil, reason.ChainMissing
	}
	return chainFromValue(v)
}

// ParseChain reads a chain from its wire bytes, as the first two checks of a verifier do, and answers
// with the stamps and OK, or with no stamps and the reason it refused them:
//
//  1. CHAIN_MISSING, unless the bytes are wire bytes, canonical and within the limit, of a non-empty
//     array whose every item is a stamp: an object of exactly a stamp's eleven members, with v the number
//     3, ts a protocol integer, every other member a string, and sig canonical base64url;
//  2. BAD_SIGNATURE, if a signed field of any stamp holds "|".
//
// Every stamp is read before any is checked for the delimiter, so a chain with both faults, in whichever
// stamps, is CHAIN_MISSING. The reader checks sig's encoding, not its length: a sig of the wrong length
// reads, and fails the signature check that follows. ParseChain never panics, whatever the bytes.
func ParseChain(wire []byte) (Chain, reason.Code) {
	v, err := json.ReadWire(wire)
	if err != nil {
		return nil, reason.ChainMissing
	}
	return chainFromValue(v)
}

func chainFromValue(v json.Value) (Chain, reason.Code) {
	items := v.Items()
	if len(items) == 0 {
		return nil, reason.ChainMissing
	}
	c := make(Chain, len(items))
	for i, item := range items {
		s, err := stampFromValue(item)
		if err != nil {
			return nil, reason.ChainMissing
		}
		c[i] = s
	}
	for _, s := range c {
		if s.fault() != nil {
			return nil, reason.BadSignature
		}
	}
	return c, reason.OK
}

func stampFromValue(o json.Value) (Stamp, error) {
	if err := json.Exactly(o, stampMembers, nil); err != nil {
		return Stamp{}, err
	}
	if v, err := json.Integer(o, "v"); err != nil || v != version {
		return Stamp{}, errors.New(`the member "v" is not 3`)
	}
	var s Stamp
	var err error
	if s.Svc, err = json.String(o, "svc"); err != nil {
		return Stamp{}, err
	}
	if s.Inst, err = json.String(o, "inst"); err != nil {
		return Stamp{}, err
	}
	if s.RID, err = json.String(o, "rid"); err != nil {
		return Stamp{}, err
	}
	if s.TS, err = json.Integer(o, "ts"); err != nil {
		return Stamp{}, err
	}
	if s.Sess, err = json.String(o, "sess"); err != nil {
		return Stamp{}, err
	}
	if s.Rcv, err = json.String(o, "rcv"); err != nil {
		return Stamp{}, err
	}
	if s.Bind, err = json.String(o, "bind"); err != nil {
		return Stamp{}, err
	}
	if s.Infl, err = json.String(o, "infl"); err != nil {
		return Stamp{}, err
	}
	if s.Prev, err = json.String(o, "prev"); err != nil {
		return Stamp{}, err
	}
	if s.Sig, err = json.String(o, "sig"); err != nil {
		return Stamp{}, err
	}
	if _, err := b64.Decode(s.Sig); err != nil {
		return Stamp{}, errors.New(`the member "sig" is not canonical base64url`)
	}
	return s, nil
}

// Wire returns the chain's wire bytes, its canonical bytes. It refuses an empty chain and a stamp that
// Stamp.Wire refuses, so a chain it writes reads back as itself.
func (c Chain) Wire() ([]byte, error) {
	if len(c) == 0 {
		return nil, errors.New("paztport stamp: the chain can't be written: it has no stamps")
	}
	items := make([]json.Value, len(c))
	for i, s := range c {
		if err := s.writable(); err != nil {
			return nil, fmt.Errorf("paztport stamp: the chain can't be written: stamp %d: %w", i, err)
		}
		items[i] = s.value()
	}
	return wire(json.Arr(items...))
}

// Token returns the chain's token, the base64url of its wire bytes. It refuses what Wire refuses.
func (c Chain) Token() (string, error) {
	b, err := c.Wire()
	if err != nil {
		return "", err
	}
	return b64.Encode(b), nil
}
