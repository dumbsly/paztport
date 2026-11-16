// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
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
	// Name is the receiver each request's last stamp must be addressed to: this service's policy name or,
	// for an embedder that names operations, that name, '#' and the operation the embedder's own routing
	// will run for the request: "payment#pay".
	Name string
	// Verifier is this service's verifier, pinned to its own policy material; nil for a service that
	// holds none, which neither verifies nor attests.
	Verifier *verify.Verifier
	// Origin reports whether this service is an entry point, which starts every request tree afresh: it
	// carries nothing a request brings, never takes a chain as verified and
	// never attests. Under a mode it still runs the live order on each request, and enforce refuses one
	// that fails. It must agree with Stamper's Origin, when there is a Stamper: see [Receiver.Accept].
	Origin bool
	// Stamper is this service's stamper; nil for a service with no stamp key, which never attests.
	Stamper *stamp.Stamper
	// Operations is this service's own operation table, or nil for a service that holds none. When Name
	// names an operation of it that declares a key, and the chain's last stamp names an operation too,
	// [Receiver.Accept] reads the request's key value from its target and verifies under the nonce key that
	// holds it, the JCS text of [rid, last svc, last rcv, key value, "req"] ([wire.RequestNonceKey]): a request
	// tree may call the operation once for each item. The table must be covered by the signed root
	// ([policy.OperationTable.CoveredBy]): a service must not use a table the root does not cover. Its Service
	// must be this receiver's, or Accept panics. Without it no key value is read, and every [Delivery] has Key "".
	Operations *policy.OperationTable
	// Extensions is this service's extension settings, for a service with no Verifier: the extensions it acts
	// on and the names it carries, by which it matches the blocks of a request it serves unverified and hands
	// their items on. Beside a Verifier the settings are the Verifier's, and this must be the zero value or equal
	// to them, or Accept panics: a service states its settings once.
	Extensions verify.Extensions
}

// Accept decides the request req, which the transport authenticated as sent by peer, or nil when it
// authenticated no one, under mode, which the adapter reads once per request so that a switch cannot
// catch a request half-way.
//
// Call it once per request: the live order spends the request's nonce key, so a second call reports
// REPLAY. Accept never panics on any request, and a request that does not verify is answered, never an
// error. ctx reaches only the verifier's nonce cache.
//
// A request whose chain passed the live order here is served as verified, and handed the verifier's hand-over.
// Every other request this service is about to serve, at any service but an origin, has its blocks matched to
// its stamps first, by check 9a (verification.md, A service never serves a request whose blocks fail check 9a):
// in audit mode after any failure, with a nonce cache that cannot answer, with Paztport off, with no verifier,
// and with a verifier but no stamper or under no mode. Blocks that fail it are refused with
// 400 {"reason":"EXTENSION_MISMATCH"}, never served, and where the chain did not read the blocks must still
// read as an array of blocks. Blocks that match are handed on as not verified ([verify.ServedUnverified]).
// Under enforce, verification refuses a request whose blocks fail check 9a itself, with 403. Then a service whose
// settings act on influence reads the items handed on, verified or not, and refuses a request holding one that
// does not read with 400 {"reason":"INFLUENCE_MISMATCH"}, in every mode (influence.md, Entries).
//
// A nonce cache that cannot answer, such as one whose store is down, leaves the request undecided, so
// Accepted.CacheErr is its error, for the embedder's own log, and the request is never verified,
// attested or given a [Accepted.Delivery]. Under [ModeEnforce] it is refused with [Unavailable], 503 and
// no body, as it cannot be shown to be no replay. Under [ModeAudit], and for a receiver with no mode,
// which refuses nothing, it is served unverified and unattested, carrying its chain and blocks once check 9a
// has held on them, as a request that fails in audit mode is.
//
// Accept panics on a receiver with no Verifier that is given ModeEnforce, ModeAudit or a value that is no
// mode: it is to verify requests with nothing to verify them with, which is a fault in the program, and
// serving them unverified would fail open. It panics, too, on a receiver whose Origin differs from its
// Stamper's: one would carry what a request brings while the other starts a new request tree, which is a
// fault in the program. So does a receiver whose Operations table is not for the service Name names, and one
// whose Extensions differ from its Verifier's.
//
// A request to a keyed operation that gives no key value (the target does not hold it exactly as
// [policy.OperationTable.KeyValue] reads it, a percent-encoded segment among them) is verified under the
// service alone, so the chain that names the operation fails the receiver check, BINDING_MISMATCH, before
// any nonce key is spent.
func (r *Receiver) Accept(ctx context.Context, req InboundRequest, peer *verify.Peer, mode Mode) Accepted {
	ext := settings(r.Verifier, r.Extensions, "receiver")
	if r.Stamper != nil && r.Stamper.Origin != r.Origin {
		panic("paztport http: a receiver's Origin and its Stamper's Origin must agree")
	}
	if r.Operations != nil && r.Operations.Service != policy.Service(r.Name) {
		panic(fmt.Sprintf("paztport http: the operation table is for %s, but the receiver is named for %s",
			r.Operations.Service, policy.Service(r.Name)))
	}
	in, chain := requestInput(req, r.Name, peer)
	key := r.readKey(req, chain, &in)
	a := Accepted{key: key, ext: ext}
	if mode != ModeOff && mode != ModeNone {
		if r.Verifier == nil {
			panic("paztport http: a receiver that verifies requests under a mode needs a Verifier")
		}
		res, err := r.Verifier.Verify(ctx, in)
		switch {
		case err != nil && mode != ModeAudit:
			return cacheFailed(err, ext)
		case err != nil:
			// No verdict, so nothing is verified, and audit serves the request unverified.
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
		// request, vouches for nothing and never attests, so it has no blocks to drop.
		return Accepted{Result: a.Result, Audit: a.Audit, CacheErr: a.CacheErr, ext: ext}
	}
	if mode != ModeOff && r.Verifier != nil && r.Stamper != nil && chain != nil && a.Result == nil &&
		a.CacheErr == nil {
		// A service with no mode verifies the chain for attestation alone, and refuses nothing. A request
		// whose nonce cache could not answer in audit mode is not verified again.
		res, err := r.Verifier.Verify(ctx, in)
		if err != nil {
			a.CacheErr = err
		} else {
			a.Result, a.Verified = &res, res.OK()
		}
	}
	if a.Verified {
		a.HandOver = a.Result.HandOver
	} else {
		h, serve := verify.ServedUnverified(in.Chain, in.Blocks, ext)
		if !serve {
			return refused(Refusal(400, reason.ExtensionMismatch), a)
		}
		a.HandOver = h
	}
	if refusal := unreadItems(ext, a.HandOver); refusal != nil {
		return refused(*refusal, a)
	}
	if chain != nil {
		blocks, ok := carried(chain, in.Blocks)
		if !ok {
			return refused(Refusal(400, reason.ExtensionMismatch), a)
		}
		a.Inbound = Inbound{Chain: chain, Blocks: blocks}
	}
	if a.Verified && r.Stamper != nil {
		a.attest = &attester{stamper: r.Stamper, chain: slices.Clone(chain)}
	}
	return a
}

// unreadItems returns the refusal of a request handed an influence item that does not read as an entry, at a
// service whose settings act on influence: 400 {"reason":"INFLUENCE_MISMATCH"}, verified or not, in every mode
// (influence.md, Entries); nil otherwise. A service that does not act on influence reads no item, and nothing
// handed on, h nil, holds none.
func unreadItems(ext verify.Extensions, h *verify.HandOver) *Answer {
	if h == nil || !ext.ActsOnName(influence.Name) {
		return nil
	}
	under, _ := h.Under(influence.Name)
	if influence.ReadRequest(under).Reads() {
		return nil
	}
	refusal := Refusal(400, reason.InfluenceMismatch)
	return &refusal
}

// readKey reads the key value of req, for a request whose chain names an operation that r.Name names and
// r.Operations declares a key for, and makes in the live order's input for it: the nonce key then holds the
// value. It returns the value, or "" for none. A keyed operation with no key value in the target is
// verified under the service alone, which the chain naming the operation fails at check 4, before any nonce
// key is spent; a chain that names no operation never carries a key value.
func (r *Receiver) readKey(req InboundRequest, chain stamp.Chain, in *verify.Input) string {
	if r.Operations == nil || chain == nil {
		return ""
	}
	last := chain[len(chain)-1]
	_, operation, named := strings.Cut(r.Name, "#")
	if !named || !strings.Contains(last.Rcv, "#") || !r.Operations.Keyed(operation) {
		return ""
	}
	path, query, _ := strings.Cut(req.Target, "?")
	value, ok := r.Operations.KeyValue(operation, path, query)
	if !ok {
		in.Receiver = policy.Service(r.Name)
		return ""
	}
	nonceKey := wire.RequestNonceKey(chain[0].RID, last.Svc, last.Rcv, value)
	in.NonceKey = &nonceKey
	return value
}

// cacheFailed returns the refusal [Unavailable] of a request whose nonce cache could not answer with
// err, under a mode that refuses, at a service with settings ext: nothing is carried from it, verified or
// attested.
func cacheFailed(err error, ext verify.Extensions) Accepted {
	answer := Unavailable()
	return Accepted{Refusal: &answer, CacheErr: err, ext: ext}
}

// refused returns the refusal answer, with the result and mode of a, the request's verdict so far, the
// nonce cache's error when it could not answer, and the service's settings; nothing is carried, handed on or
// attested.
func refused(answer Answer, a Accepted) Accepted {
	return Accepted{Refusal: &answer, Result: a.Result, Audit: a.Audit, CacheErr: a.CacheErr, ext: a.ext}
}
