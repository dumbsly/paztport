// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/chaincheck"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Peer is the sender a transport authenticated, such as by an mTLS certificate.
type Peer struct {
	// Svc is the sender's service name, which check 12 compares with the last signer's.
	Svc string
	// Inst is the transport's address for the sender. It is not signed, and is never compared.
	Inst string
}

// Result is a verifier's verdict.
type Result struct {
	// Reason is OK, or the reason the chain was refused.
	Reason reason.Code
	// SuspectSvc and SuspectInst name the party a responder may act against, or are both "" when the
	// result names no one. They are for the verifier's own logs and events, never for the caller.
	SuspectSvc, SuspectInst string
}

// OK reports whether every check held.
func (r Result) OK() bool {
	return r.Reason == reason.OK
}

// Input is what one request brings: the tokens that arrived with it, and what the receiver knows of it.
// A nil token is absent; an empty one is present, and is read as what it is.
type Input struct {
	// Chain is the chain's token.
	Chain *string
	// ExpectedBind is the binding the receiver computed for what it received. A nil one never matches.
	ExpectedBind *string
	// Influence is the influence's token. A nil one is the empty list.
	Influence *string
	// Proof is the route proof's token. A nil one proves nothing.
	Proof *string
	// Receiver is what the last stamp's rcv must name: the receiver's own policy name, from its
	// configuration and never from the request, or for a response, the calling client's svc.
	Receiver string
	// ReceiverInRoute reports whether the route ends at Receiver: true for a call, false for a response.
	ReceiverInRoute bool
	// NonceKey is the chain's key in the replay cache. A nil one is a replay.
	NonceKey *string
	// Peer is the sender the transport authenticated, or nil.
	Peer *Peer
}

// Verifier checks chains received live, against the Config it was built with. It is safe for use by
// many goroutines when its nonce cache and clock are. Use New; the zero Verifier is not usable.
type Verifier struct {
	cfg Config
}

// New returns a verifier for cfg. The verifier keeps its own copy of cfg's keyring, its every key
// included, its root and its allowed origins, so later changes to them do not reach it. New panics if cfg
// has no clock or no nonce cache: no verifier can run without them, and that is a fault in the program,
// not in any request.
func New(cfg Config) *Verifier {
	if cfg.Now == nil || cfg.Nonces == nil {
		panic("paztport verify: a Config needs a clock and a nonce cache")
	}
	keyring := make(policy.Keyring, len(cfg.Keyring))
	for svc, key := range cfg.Keyring {
		keyring[svc] = slices.Clone(key)
	}
	cfg.Keyring = keyring
	cfg.Root = slices.Clone(cfg.Root)
	cfg.AllowedOrigins = slices.Clone(cfg.AllowedOrigins)
	return &Verifier{cfg: cfg}
}

// Verify runs the live order on in, and answers with the first check that fails, or OK:
//
//  0. POLICY_EXPIRED, if the Config's PolicyNotAfter is outside [0, 2^53 - 1] or the clock is past it;
//  1. CHAIN_MISSING, unless the chain reads from its token;
//  2. BAD_SIGNATURE, if a signed field of any stamp holds "|";
//  3. BAD_ORIGIN, unless the origin is an allowed origin;
//  4. BAD_SIGNATURE, BROKEN_LINK, then BINDING_MISMATCH, unless each stamp in turn is signed by its
//     service's key and links to the one before, and then each stamp's rcv names the next stamp's svc and
//     the last's names the receiver;
//  5. RID_MISMATCH, unless every stamp carries the origin's rid;
//  6. SESSION_UNKNOWN, unless every stamp carries the Config's session;
//  7. EXPIRED, unless the last stamp's ts is within the call window of now, either way, and the origin's
//     is at most the run window before now and the call window after it;
//  8. BINDING_MISMATCH, unless the last stamp binds the expected binding;
//  9. INFLUENCE_MISMATCH, unless the influence reads and the last stamp commits to it;
//  10. REPLAY, unless there is a nonce key, the cache remembers keys for at least twice the call window,
//     and the key is new to it; only then is the key recorded;
//  11. PATH_NOT_ALLOWED, unless the proof proves the route against the pinned root;
//  12. PEER_MISMATCH, if there is a peer and it is not the last signer.
//
// POLICY_EXPIRED names no one. With a peer, every other result names the peer; without one, OK and
// PATH_NOT_ALLOWED name the last stamp's svc and inst, and every other result names no one.
//
// Verify never panics on any input, and a malformed input is a result, never an error. ctx reaches only
// the nonce cache. The error is the cache's, when it could not answer, ctx's cancellation or deadline
// included; the Result is then the zero Result, which is not OK.
func (v *Verifier) Verify(ctx context.Context, in Input) (Result, error) {
	now := v.cfg.Now()
	// 0. The pinned policy is still vouched for. This is about the verifier's own material, not the
	// request, so it comes first, names no one and spends no nonce key.
	if v.cfg.PolicyNotAfter < 0 || v.cfg.PolicyNotAfter > json.MaxSafe || now > v.cfg.PolicyNotAfter {
		return Result{Reason: reason.PolicyExpired}, nil
	}
	code, last, err := v.check(ctx, in, now)
	if err != nil {
		return Result{}, err
	}
	r := Result{Reason: code}
	switch {
	case in.Peer != nil:
		r.SuspectSvc, r.SuspectInst = in.Peer.Svc, in.Peer.Inst
	case code == reason.OK || code == reason.PathNotAllowed:
		r.SuspectSvc, r.SuspectInst = last.Svc, last.Inst
	}
	return r, nil
}

// check runs checks 1 to 12 and returns the first code that fails, or OK, with the chain's last stamp
// once the chain has read.
func (v *Verifier) check(ctx context.Context, in Input, now int64) (reason.Code, stamp.Stamp, error) {
	// 1-2. The chain reads, and no signed field holds the delimiter.
	if in.Chain == nil {
		return reason.ChainMissing, stamp.Stamp{}, nil
	}
	c, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return code, stamp.Stamp{}, nil
	}
	origin, last := c[0], c[len(c)-1]

	// 3-6. The origin, signatures and links, receivers, rid and session.
	if code := chaincheck.Stamps(c, v.cfg.Keyring, v.cfg.AllowedOrigins, v.cfg.Sess, in.Receiver, nil); code != reason.OK {
		return code, last, nil
	}

	// 7. Freshness.
	if !fresh(now, origin.TS, last.TS, v.cfg.CallMaxAgeMs, v.cfg.RunMaxAgeMs) {
		return reason.Expired, last, nil
	}

	// 8-9. The binding and the influence commitment.
	if code := chaincheck.Commitments(last, in.ExpectedBind, in.Influence); code != reason.OK {
		return code, last, nil
	}

	// 10. Replay. A cache that forgets sooner than twice the call window could forget a key while a replay
	// of it is still fresh, so it fails closed before the key is spent.
	ttl := v.cfg.Nonces.TTL()
	if in.NonceKey == nil || ttl < 0 || ttl/2 < v.cfg.CallMaxAgeMs {
		return reason.Replay, last, nil
	}
	seen, err := v.cfg.Nonces.SeenBefore(ctx, *in.NonceKey, now)
	if err != nil {
		return "", last, err
	}
	if seen {
		return reason.Replay, last, nil
	}

	// 11. The route.
	if code := chaincheck.Route(c, in.Receiver, in.ReceiverInRoute, in.Proof, v.cfg.Root, v.cfg.RootID); code != reason.OK {
		return code, last, nil
	}

	// 12. The peer is the last signer. It runs last, so every other check keeps its code when a transport
	// adds a peer.
	if in.Peer != nil && in.Peer.Svc != last.Svc {
		return reason.PeerMismatch, last, nil
	}
	return reason.OK, last, nil
}

// fresh runs check 7's arithmetic on the origin's and the last stamp's ts: the last is within call of
// now, either way, and the origin at most run before now and at most call after it. A difference too
// large for an int64 is outside every window, so no clock or window makes the check pass by wrapping.
func fresh(now, origin, last, call, run int64) bool {
	return exact.AtMost(now, last, call) && exact.AtMost(last, now, call) &&
		exact.AtMost(now, origin, run) && exact.AtMost(origin, now, call)
}
