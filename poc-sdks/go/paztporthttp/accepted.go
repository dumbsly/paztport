// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Accepted is what [Receiver.Accept] decided about one request: a refusal to send in place of the
// handler's answer, or what the handler starts from, and whether its answer may be attested. The
// embedder carries it for the handler's own calls and decisions.
//
// The zero Accepted serves nothing as verified and attests nothing: it is work outside any request.
type Accepted struct {
	// Refusal is the answer to send in place of the handler's, or nil when the request is served.
	Refusal *Answer
	// Inbound is the chain the request carried, for the handler's own calls to stamp onto. It is nil
	// when none came, it did not read, the request was refused, or this service is an origin, which
	// starts a new request tree.
	Inbound stamp.Chain
	// Verified reports whether Inbound passed the live order at this hop, so that Influence is the one
	// its caller committed to. A chain that failed in audit mode, was not checked (the hop is off, or has
	// nothing to verify with), whose nonce cache could not answer or came to an origin is not verified.
	Verified bool
	// Influence is what the handler starts from: the entries the request carried, which are the ones its
	// last stamp commits to when Verified. It is empty at an origin and for a refusal.
	Influence []influence.Entry
	// Result is the live order's result on the request, or nil when it did not run or its nonce cache
	// could not answer. Under a mode it is the result to report; for a service with no mode it decided
	// only whether to attest. The embedder may build an event from it; the caller is never told it.
	Result *verify.Result
	// Audit reports that Result came from verification in audit mode, so an event built from it is an
	// audit event.
	Audit bool
	// CacheErr is the nonce cache's error, when it could not answer, for the embedder's own log; nil
	// otherwise. The request is then undecided: it is refused with [Unavailable] under enforce, and
	// otherwise served unverified and unattested, with no Result, carrying the chain and the influence as
	// received; influence that does not read is still refused 400.
	CacheErr error

	attest *attester // nil unless the answer is attested
}

// attester is what an attested answer is stamped with: this service's stamper and the chain the request
// carried, held apart from Inbound, so that nothing the handler does to Inbound changes what is vouched
// for.
type attester struct {
	stamper *stamp.Stamper
	chain   stamp.Chain
}

// Delivery names the delivery of a request that was verified at this hop: the rid its first stamp
// carries, and the signer and request binding of its last stamp. It is false for a request that was not
// verified, such as one at an origin, with the hop off, that failed in audit mode or whose nonce cache
// could not answer. Two deliveries of one request give the same key, so the application can tell a
// request it has already handled.
func (a Accepted) Delivery() (Delivery, bool) {
	if !a.Verified || len(a.Inbound) == 0 {
		return Delivery{}, false
	}
	last := a.Inbound[len(a.Inbound)-1]
	return Delivery{RID: a.Inbound[0].RID, Svc: last.Svc, Bind: last.Bind}, true
}

// Delivery is the key of one delivery of a verified request, for the application's own idempotency
// handling: the request's rid, which its first stamp carries, and the signer (Svc) and request binding
// (Bind) of its last stamp, which name the hop that sent this call and the call itself.
//
// The key (RID, Svc) names the delivery, and with a peer (mutual TLS) no one but that signer can send
// it. The same key and Bind is the same request sent again by that signer. The same key with another
// Bind is a different request under a reused key, to refuse. A user's second click or a client's own
// resend is a new rid, and needs the application's own idempotency key.
type Delivery struct {
	RID, Svc, Bind string
}

// Attests reports whether the answer to the request is attested: only when its chain passed the live
// order here, at a service that is not an origin, holds a stamp key and a verifier, and is not switched
// off. An adapter holds the handler's body until it is complete only when this is true.
func (a Accepted) Attests() bool {
	return a.attest != nil
}

// Attest returns the X-Path-Response header for the handler's complete answer, status and body,
// labelled with labels in order, and true: one stamp on the chain the request carried, back to its
// caller, binding the answer's result hash, the request's rid and the labels. It takes the answer whole,
// so an adapter calls it only once nothing will change the body; an answer it cannot hold whole is one
// to send unattested.
//
// It returns false, and no header, when the answer is not attested: when [Accepted.Attests] is false,
// or when the binding cannot carry the request's rid or a label, such as a rid holding a newline. The
// caller then counts the answer untrusted, which is always safe. The error is for a stamper that cannot
// sign, such as one with no key.
func (a Accepted) Attest(status int, body []byte, labels []influence.Label) (string, bool, error) {
	if a.attest == nil {
		return "", false, nil
	}
	hash := wire.ResultHash(status, body)
	rid := a.attest.chain[0].RID
	if _, err := stamp.ResponseBinding(hash, rid, labels); err != nil {
		return "", false, nil
	}
	s, err := a.attest.stamper.Respond(a.attest.chain, hash, rid, labels)
	if err != nil {
		return "", false, err
	}
	h, err := wire.EncodeResponse(s, labels)
	if err != nil {
		return "", false, err
	}
	return h, true, nil
}
