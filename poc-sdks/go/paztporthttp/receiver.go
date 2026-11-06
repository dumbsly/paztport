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
	// that fails. It must agree with Stamper's Origin, when there is a Stamper: see [Receiver.Accept].
	Origin bool
	// Stamper is this service's stamper; nil for a service with no stamp key, which never attests.
	Stamper *stamp.Stamper
}

// Accept decides the request req, which the transport authenticated as sent by peer, or nil when it
// authenticated no one, under mode, which the adapter reads once per request so that a switch cannot
// catch a request half-way.
//
// Call it once per request: the live order spends the request's nonce key, so a second call reports
// REPLAY. Accept never panics on any request, and a request that does not verify is answered, never an
// error. ctx reaches only the verifier's nonce cache.
//
// A nonce cache that cannot answer, such as one whose store is down, leaves the request undecided, so
// Accepted.CacheErr is its error, for the embedder's own log, and the request is never verified,
// attested or given a [Accepted.Delivery]. Under [ModeEnforce] it is refused with [Unavailable], 503 and
// no body, as it cannot be shown to be no replay. Under [ModeAudit], and for a receiver with no mode,
// which refuses nothing, it is served unverified and unattested, carrying the chain and the influence
// as received, as a request that fails in audit mode is; influence that does not read is still refused.
//
// Accept panics on a receiver with no Verifier that is given ModeEnforce, ModeAudit or a value that is no
// mode: it is to verify requests with nothing to verify them with, which is a fault in the program, and
// serving them unverified would fail open. It panics, too, on a receiver whose Origin differs from its
// Stamper's: one would carry what a request brings while the other starts a new request tree, which is a
// fault in the program.
func (r *Receiver) Accept(ctx context.Context, req InboundRequest, peer *verify.Peer, mode Mode) Accepted {
	if r.Stamper != nil && r.Stamper.Origin != r.Origin {
		panic("paztport http: a receiver's Origin and its Stamper's Origin must agree")
	}
	in, chain := requestInput(req, r.Name, peer)
	a := Accepted{Inbound: chain}
	if mode != ModeOff && mode != ModeNone {
		if r.Verifier == nil {
			panic("paztport http: a receiver that verifies requests under a mode needs a Verifier")
		}
		res, err := r.Verifier.Verify(ctx, in)
		switch {
		case err != nil && mode != ModeAudit:
			return cacheFailed(err)
		case err != nil:
			// No verdict, so nothing is verified, and audit serves the request as received.
			a.CacheErr = err
		default:
			a.Result, a.Audit = &res, mode == ModeAudit
			if !res.OK() && !a.Audit {
				return refused(Refusal(403, res.Reason), a)
			}
			a.Verified = res.OK() && chain != nil
		}
	}
	if r.Origin {
		// An origin starts the request tree afresh: whatever its verdict, it carries nothing from the
		// request, vouches for nothing and never attests.
		return Accepted{Result: a.Result, Audit: a.Audit, CacheErr: a.CacheErr}
	}
	es, ok := readInfluence(req.Influence)
	if !ok {
		return refused(Refusal(400, reason.InfluenceMismatch), a)
	}
	a.Influence = es
	if mode == ModeOff || r.Verifier == nil || r.Stamper == nil || chain == nil {
		return a
	}
	if a.Result == nil && a.CacheErr == nil {
		// A service with no mode verifies the chain for attestation alone, and refuses nothing. A request
		// whose nonce cache could not answer in audit mode is not verified again.
		res, err := r.Verifier.Verify(ctx, in)
		if err != nil {
			a.CacheErr = err
			return a
		}
		a.Result, a.Verified = &res, res.OK()
	}
	if a.Verified {
		a.attest = &attester{stamper: r.Stamper, chain: slices.Clone(chain)}
	}
	return a
}

// cacheFailed returns the refusal [Unavailable] of a request whose nonce cache could not answer with
// err, under a mode that refuses: nothing is carried from it, verified or attested.
func cacheFailed(err error) Accepted {
	answer := Unavailable()
	return Accepted{Refusal: &answer, CacheErr: err}
}

// refused returns the refusal answer, with the result and mode of a, the request's verdict so far, and
// the nonce cache's error when it could not answer.
func refused(answer Answer, a Accepted) Accepted {
	return Accepted{Refusal: &answer, Result: a.Result, Audit: a.Audit, CacheErr: a.CacheErr}
}
