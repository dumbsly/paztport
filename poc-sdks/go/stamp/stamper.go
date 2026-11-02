// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// errNoInbound refuses to stamp onto a chain that is not there.
var errNoInbound = errors.New("paztport stamp: there is no inbound chain to stamp onto")

// Stamper stamps one service's outbound calls and its responses. It is framework-neutral: a transport
// hands it the chain a request arrived with and the binding of what it is about to send, and sends what
// comes back.
//
// An origin starts a chain; any other service appends to the one it received, and refuses to stamp
// without one, because only entry points start chains. Every stamp carries its own time.
//
// A Stamper never changes itself, so it is safe for concurrent use if its NewRID and Now are.
type Stamper struct {
	// Svc is the service the stamper signs as: every stamp's svc.
	Svc string
	// Inst is the service's instance, as it reports it.
	Inst string
	// Key is the service's Ed25519 private key.
	Key ed25519.PrivateKey
	// Origin reports whether the service is an entry point, which starts each request's chain.
	Origin bool
	// NewRID returns a fresh request id for each chain an origin starts. Only an origin needs it.
	NewRID func() string
	// Now returns the time, in milliseconds since the Unix epoch, that a stamp is signed at.
	Now func() int64
}

// Next stamps an outbound call to receiver, committing the influence infl that shaped it, and returns the
// chain to send and the bundle's proof for the route it completes: the chain's services, then receiver.
// The proof is nil when the bundle holds none.
//
// An origin starts a chain of one stamp, with a new rid, sess "" and prev "", and ignores inbound. Any
// other service appends a stamp to inbound with inbound's rid, its last stamp's sess and that stamp's sig
// as prev; inbound itself is not changed, and without it there is nothing to stamp onto. Next also
// refuses fields that Sign refuses and influence that influence.Commit refuses.
func (s *Stamper) Next(
	inbound Chain, receiver, bind string, infl []influence.Entry, bundle policy.ProofBundle,
) (Chain, *policy.Proof, error) {
	var chain Chain
	var rid, sess, prev string
	if s.Origin {
		if s.NewRID == nil {
			return nil, nil, errors.New("paztport stamp: an origin stamper has no NewRID")
		}
		rid = s.NewRID()
	} else {
		if len(inbound) == 0 {
			return nil, nil, errNoInbound
		}
		last := inbound[len(inbound)-1]
		chain = append(make(Chain, 0, len(inbound)+1), inbound...)
		rid, sess, prev = inbound[0].RID, last.Sess, last.Sig
	}
	st, err := s.sign(rid, sess, receiver, bind, infl, prev)
	if err != nil {
		return nil, nil, err
	}
	chain = append(chain, st)

	route := make([]string, 0, len(chain)+1)
	for _, hop := range chain {
		route = append(route, hop.Svc)
	}
	return chain, proof(bundle, append(route, receiver)...), nil
}

// Boundary stamps the call that leaves this organisation for partnerEntry, the partner's entry service,
// inside the session sess, committing the blinded influence sent. It returns a chain of that one stamp
// and the bundle's proof for the route Svc/partnerEntry, or nil when the bundle holds none.
//
// The stamp stands alone: prev is "", because the partner holds only this service's key, not the keys of
// the internal chain's signers, whose stamps stay here as evidence. It carries the internal chain's rid.
// Boundary refuses an empty sess, since a stamp with prev "" and no session would be a valid in-mesh
// origin stamp, and an empty chain.
//
// Boundary checks nothing about verified but that it has stamps. The boundary stamp vouches for the
// request that led to it, so pass only a chain that passed the live order at this service.
func (s *Stamper) Boundary(
	verified Chain, sess, partnerEntry, bind string, sent []influence.Entry, bundle policy.ProofBundle,
) (Chain, *policy.Proof, error) {
	if len(verified) == 0 {
		return nil, nil, errNoInbound
	}
	if sess == "" {
		return nil, nil, errors.New("paztport stamp: a boundary stamp needs a session id")
	}
	st, err := s.sign(verified[0].RID, sess, partnerEntry, bind, sent, "")
	if err != nil {
		return nil, nil, err
	}
	return Chain{st}, proof(bundle, s.Svc, partnerEntry), nil
}

// Respond stamps the response to the request whose chain is inbound: one more stamp on that chain, which
// the caller appends to the chain it sent. Its rcv is the caller, the last stamp's svc; its rid and sess
// are the request's; its bind is ResponseBinding(resultHash, callID, labels); its infl is "", since the
// labels are in the binding; and its prev is the last stamp's sig. Over HTTP, resultHash is the HTTP
// result hash of the status and body sent, and callID the request's rid.
//
// A response stamp is shaped like a request stamp, so on a chain nobody checked it would let anyone mint
// stamps under this service's key: an origin's response to a forged one-stamp chain with an empty sig is
// a valid origin stamp. So an origin never responds, and Respond refuses to; any other service passes
// only a chain that passed the live order here. Respond also refuses an empty chain and a binding that
// ResponseBinding refuses.
func (s *Stamper) Respond(inbound Chain, resultHash, callID string, labels []influence.Label) (Stamp, error) {
	if s.Origin {
		return Stamp{}, errors.New("paztport stamp: an origin never responds")
	}
	if len(inbound) == 0 {
		return Stamp{}, errNoInbound
	}
	bind, err := ResponseBinding(resultHash, callID, labels)
	if err != nil {
		return Stamp{}, err
	}
	last := inbound[len(inbound)-1]
	return s.sign(inbound[0].RID, last.Sess, last.Svc, bind, nil, last.Sig)
}

// sign signs a stamp by this service at the time Now gives, committing infl.
func (s *Stamper) sign(rid, sess, rcv, bind string, infl []influence.Entry, prev string) (Stamp, error) {
	if s.Now == nil {
		return Stamp{}, errors.New("paztport stamp: the stamper has no clock")
	}
	commit, err := influence.Commit(infl)
	if err != nil {
		return Stamp{}, fmt.Errorf("paztport stamp: the influence can't be committed: %w", err)
	}
	return Sign(Stamp{
		Svc: s.Svc, Inst: s.Inst, RID: rid, TS: s.Now(), Sess: sess, Rcv: rcv, Bind: bind, Infl: commit, Prev: prev,
	}, s.Key)
}

// proof returns the bundle's proof for the route through nodes, or nil when it holds none.
func proof(bundle policy.ProofBundle, nodes ...string) *policy.Proof {
	p, ok := bundle.ProofFor(policy.JoinRoute(nodes...))
	if !ok {
		return nil
	}
	return &p
}
