// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"context"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Receiver is one service's receiver of requests over HTTP. Given a request as it arrived and the peer
// the transport authenticated, [Receiver.Accept] decides whether it is refused, what its handler starts
// from, and whether its answer is attested.
//
// A Receiver never changes itself, so it is safe for concurrent use when its Verifier and Stamper are.
type Receiver struct {
	// Name is this service's policy name, which each request's last stamp must be addressed to.
	Name string
	// Verifier is this service's verifier, pinned to its own policy material; nil for a service that
	// holds none, which neither verifies nor attests.
	Verifier *verify.Verifier
	// Origin reports whether this service is an entry point, which starts every request tree afresh: it
	// carries neither the chain nor the influence a request brings, never takes a chain as verified and
	// never attests. Under a mode it still runs the live order on each request, and enforce refuses one
	// that fails.
	Origin bool
	// Stamper is this service's stamper; nil for a service with no stamp key, which never attests.
	Stamper *stamp.Stamper
}

// Accept decides the request req, which the transport authenticated as sent by peer, or nil when it
// authenticated no one, under mode, which the adapter reads once per request so that a switch cannot
// catch a request half-way.
//
// Accept never panics on any request, and a request that does not verify is answered, never an error.
// ctx reaches only the verifier's nonce cache. The error is the cache's, when it could not answer, and
// comes with the zero Accepted, so the adapter fails the request.
//
// Accept panics on a receiver with no Verifier that is given ModeEnforce, ModeAudit or a value that is
// no mode: it is to verify requests with nothing to verify them with, which
// is a fault in the program, and serving them unverified would fail open.
func (r *Receiver) Accept(ctx context.Context, req InboundRequest, peer *verify.Peer, mode Mode) (Accepted, error) {
	in, chain := requestInput(req, r.Name, peer)
	a := Accepted{Inbound: chain}
	if mode != ModeOff && mode != ModeNone {
		if r.Verifier == nil {
			panic("paztport http: a receiver that verifies requests under a mode needs a Verifier")
		}
		res, err := r.Verifier.Verify(ctx, in)
		if err != nil {
			return Accepted{}, err
		}
		a.Result, a.Audit = &res, mode == ModeAudit
		if !res.OK() && !a.Audit {
			return refused(Refusal(403, res.Reason), a), nil
		}
		a.Verified = res.OK() && chain != nil
	}
	if r.Origin {
		// An origin starts the request tree afresh: whatever its verdict, it carries nothing from the
		// request, vouches for nothing and never attests.
		return Accepted{Result: a.Result, Audit: a.Audit}, nil
	}
	es, ok := readInfluence(req.Influence)
	if !ok {
		return refused(Refusal(400, reason.InfluenceMismatch), a), nil
	}
	a.Influence = es
	if mode == ModeOff || r.Verifier == nil || r.Stamper == nil || chain == nil {
		return a, nil
	}
	if a.Result == nil {
		// A service with no mode verifies the chain for attestation alone, and refuses nothing.
		res, err := r.Verifier.Verify(ctx, in)
		if err != nil {
			return Accepted{}, err
		}
		a.Result, a.Verified = &res, res.OK()
	}
	if a.Verified {
		a.attest = &attester{stamper: r.Stamper, chain: slices.Clone(chain)}
	}
	return a, nil
}

// refused returns the refusal answer, with the result and mode of a, the request's verdict so far.
func refused(answer Answer, a Accepted) Accepted {
	return Accepted{Refusal: &answer, Result: a.Result, Audit: a.Audit}
}
