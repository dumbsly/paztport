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
	// Svc is the sender's service name, which check 10 compares with the last signer's.
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
	// HandOver is what the service is handed for the extensions it acts on, verified: non-nil exactly when
	// Reason is OK. A refusal hands nothing over, so refusals still compare with ==.
	HandOver *HandOver
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
	// Blocks is the token of the blocks received with the chain, one per stamp. A nil one, no token received, is
	// one empty block per stamp; a token that reads as JSON null is not.
	Blocks *string
	// Proof is the route proof's token. A nil one proves nothing.
	Proof *string
	// Receiver is what the last stamp's rcv must equal: the receiver's own policy name, with the operation the
	// call invokes when the route names one, from its configuration and never from the request, or for a
	// response, the calling client's svc.
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

// New returns a verifier for cfg. The verifier keeps its own copy of cfg's keyrings, their every key
// included, its roots and its allowed origins, so later changes to them do not reach it. New panics if cfg
// has no clock or no nonce cache: no verifier can run without them, and that is a fault in the program,
// not in any request. A cfg with no keyring or no root is not a fault: its verifier refuses every chain.
func New(cfg Config) *Verifier {
	if cfg.Now == nil {
		panic("paztport verify: Config.Now must be a clock")
	}
	if cfg.Nonces == nil {
		panic("paztport verify: Config.Nonces must be a nonce cache")
	}
	keyrings := make([]PinnedKeyring, len(cfg.Keyrings))
	for i, k := range cfg.Keyrings {
		keys := make(policy.Keyring, len(k.Keys))
		for svc, key := range k.Keys {
			keys[svc] = slices.Clone(key)
		}
		keyrings[i] = PinnedKeyring{Keys: keys, NotAfter: k.NotAfter}
	}
	roots := make([]PinnedRoot, len(cfg.Roots))
	for i, r := range cfg.Roots {
		roots[i] = PinnedRoot{Root: slices.Clone(r.Root), RootID: r.RootID, NotAfter: r.NotAfter}
	}
	cfg.Keyrings, cfg.Roots = keyrings, roots
	cfg.AllowedOrigins = slices.Clone(cfg.AllowedOrigins)
	return &Verifier{cfg: cfg}
}

// current returns the keys of the verifier's keyrings and the roots that are current at now, in their
// order.
func (v *Verifier) current(now int64) ([]policy.Keyring, []chaincheck.Root) {
	var keyrings []policy.Keyring
	for _, k := range v.cfg.Keyrings {
		if chaincheck.Current(k.NotAfter, now) {
			keyrings = append(keyrings, k.Keys)
		}
	}
	var roots []chaincheck.Root
	for _, r := range v.cfg.Roots {
		if chaincheck.Current(r.NotAfter, now) {
			roots = append(roots, chaincheck.Root{Bytes: r.Root, RootID: r.RootID})
		}
	}
	return keyrings, roots
}

// Extensions returns the extension settings the verifier's Config holds: the names checks 9b and 9c read and its
// hand-over carries. A transport reads them from here, so a service cannot verify under one actsOn and build its
// blocks or read what it is handed under another.
func (v *Verifier) Extensions() Extensions {
	return v.cfg.Extensions
}

// Verify runs the live order on in (verification.md, The live order), and answers with the first check that
// fails, or OK:
//
//  0. POLICY_EXPIRED, if the Config's PolicyNotAfter is outside [0, 2^53 - 1] or the clock is past it;
//  1. CHAIN_MISSING, unless the chain reads from its token;
//  2. BAD_ORIGIN, unless the origin is an allowed origin;
//  3. BAD_SIGNATURE, then BROKEN_LINK, unless each stamp in turn is signed under one of the keys the current
//     keyrings give its service and links to the one before;
//  4. BINDING_MISMATCH, unless each stamp's rcv addresses the next stamp's svc, by name or as svc#operation,
//     and the last's is the receiver exactly;
//  5. RID_MISMATCH, unless every stamp carries the origin's rid;
//  6. SESSION_UNKNOWN, unless every stamp carries the Config's session;
//  7. EXPIRED, unless the last stamp's ts is within the call window of now, either way, and the origin's
//     is at most the run window before now and the call window after it;
//  8. BINDING_MISMATCH, unless the last stamp binds the expected binding;
//  9. the blocks: 9a, EXTENSION_MISMATCH, unless they read, one per stamp, each committing to its stamp's
//     ext; then 9b, EXTENSION_NOT_ALLOWED, if a block holds a name the Config's settings do not carry; then
//     9c, EXTENSION_REQUIRED, if the last block requires an extension the settings do not act on;
//  10. PEER_MISMATCH, if there is a peer and it is not the last signer;
//  11. REPLAY, unless there is a nonce key, the cache remembers keys for at least twice the call window,
//     and the key is new to it; only then is the key recorded;
//  12. PATH_NOT_ALLOWED, unless the proof proves the route against a current root with its rootId.
//
// On OK the Result's HandOver holds, for each extension the settings act on, one entry per stamp, verified.
//
// A keyring or root is current while the clock is at most its own notAfter, and the verifier judges which
// are current once for each request. Check 0 is the Config's PolicyNotAfter alone, which Pinned sets to the
// last moment some keyring and some root are current.
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
	code, last, h, err := v.check(ctx, in, now)
	if err != nil {
		return Result{}, err
	}
	r := Result{Reason: code, HandOver: h}
	switch {
	case in.Peer != nil:
		r.SuspectSvc, r.SuspectInst = in.Peer.Svc, in.Peer.Inst
	case code == reason.OK || code == reason.PathNotAllowed:
		r.SuspectSvc, r.SuspectInst = last.Svc, last.Inst
	}
	return r, nil
}

// check runs checks 1 to 12 and returns the first code that fails, or OK with the hand-over, with the chain's
// last stamp once the chain has read.
func (v *Verifier) check(ctx context.Context, in Input, now int64) (reason.Code, stamp.Stamp, *HandOver, error) {
	// 1. The chain reads.
	if in.Chain == nil {
		return reason.ChainMissing, stamp.Stamp{}, nil, nil
	}
	c, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return code, stamp.Stamp{}, nil, nil
	}
	origin, last := c[0], c[len(c)-1]

	// 2-6. The origin, signatures and links, receivers, rid and session, under the keyrings current now.
	keyrings, roots := v.current(now)
	if code := chaincheck.Stamps(c, keyrings, v.cfg.AllowedOrigins, v.cfg.Sess, in.Receiver, nil); code != reason.OK {
		return code, last, nil, nil
	}

	// 7. Freshness.
	if !fresh(now, origin.TS, last.TS, v.cfg.CallMaxAgeMs, v.cfg.RunMaxAgeMs) {
		return reason.Expired, last, nil, nil
	}

	// 8. The binding.
	if code := chaincheck.Binding(last, in.ExpectedBind); code != reason.OK {
		return code, last, nil, nil
	}

	// 9a-9c. The blocks, matched to their stamps before any name in them is believed; 9c, live.
	ext := v.cfg.Extensions
	bs, code := chaincheck.Blocks(c, in.Blocks, ext.Carries, ext.ActsOnName, true)
	if code != reason.OK {
		return code, last, nil, nil
	}

	// 10. The peer is the last signer, before the nonce is touched: a request another peer sends spends
	// nothing and blames no signer.
	if in.Peer != nil && in.Peer.Svc != last.Svc {
		return reason.PeerMismatch, last, nil, nil
	}

	// 11. Replay. A cache that forgets sooner than twice the call window could forget a key while a replay
	// of it is still fresh, so it fails closed before the key is spent.
	ttl := v.cfg.Nonces.TTL()
	if in.NonceKey == nil || ttl < 0 || ttl/2 < v.cfg.CallMaxAgeMs {
		return reason.Replay, last, nil, nil
	}
	seen, err := v.cfg.Nonces.SeenBefore(ctx, *in.NonceKey, now)
	if err != nil {
		return "", last, nil, err
	}
	if seen {
		return reason.Replay, last, nil, nil
	}

	// 12. The route, against the roots current now.
	if code := chaincheck.Route(c, in.ReceiverInRoute, in.Proof, roots); code != reason.OK {
		return code, last, nil, nil
	}
	return reason.OK, last, NewHandOver(true, c, bs, ext), nil
}

// fresh runs check 7's arithmetic on the origin's and the last stamp's ts: the last is within call of
// now, either way, and the origin at most run before now and at most call after it. A difference too
// large for an int64 is outside every window, so no clock or window makes the check pass by wrapping.
func fresh(now, origin, last, call, run int64) bool {
	return exact.AtMost(now, last, call) && exact.AtMost(last, now, call) &&
		exact.AtMost(now, origin, run) && exact.AtMost(origin, now, call)
}
