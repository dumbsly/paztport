// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Root is a pinned root as check 11 uses it: the bytes of the root of an allowed routes' tree, and the
// rootId that labels the tree. Roots that share a rootId are renewals of one tree.
type Root struct {
	// Bytes is the root's bytes.
	Bytes []byte
	// RootID labels the tree.
	RootID string
}

// Current reports whether a member pinned until notAfter, in milliseconds since the Unix epoch, is
// current at at: its window is math.MaxInt64, which is no window, or an integer in [0, 2^53 - 1], and at
// is no later than it. A member under any other window is current at no time. A verifier judges its
// keyrings and roots with this once, at its own time, and hands only the current ones to the checks.
func Current(notAfter, at int64) bool {
	return (notAfter == math.MaxInt64 || 0 <= notAfter && notAfter <= json.MaxSafe) && at <= notAfter
}

// KeysFor returns the keys keyrings give svc, looked up by svc's own name in each, in the keyrings'
// order, each distinct key once: a key two keyrings share is tried once. It is empty when no keyring has
// a key under that name. The event responder looks its signers' keys up with it too.
func KeysFor(keyrings []policy.Keyring, svc string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, keyring := range keyrings {
		key, ok := keyring[svc]
		if ok && !slices.ContainsFunc(out, func(k ed25519.PublicKey) bool { return bytes.Equal(k, key) }) {
			out = append(out, key)
		}
	}
	return out
}

// Stamps runs checks 3 to 6 on c, a chain the reader has read, and answers with the first that fails:
//
//  3. BAD_ORIGIN, unless the origin's svc is one of origins;
//  4. for each stamp in order, BAD_SIGNATURE unless some keyring of keyrings, the current ones, holds a
//     key under its svc and its sig verifies under one of the keys they give it, then BROKEN_LINK unless
//     its prev is "" at the origin and the previous stamp's sig otherwise; only once every stamp has passed
//     that, BINDING_MISMATCH unless each stamp's rcv addresses the next stamp's svc, which is the svc itself or
//     the svc, '#' and a non-empty operation, and the last stamp's rcv is receiver exactly;
//  5. RID_MISMATCH unless every stamp carries rid, or the origin's rid when rid is nil;
//  6. SESSION_UNKNOWN unless every stamp carries sess.
//
// It answers OK when all hold. Checking the receivers only after the signature loop means a forged chain
// is reported as forged, not as misdirected. An empty chain, which no reader returns, is CHAIN_MISSING.
func Stamps(
	c stamp.Chain, keyrings []policy.Keyring, origins []string, sess, receiver string, rid *string,
) reason.Code {
	if len(c) == 0 {
		return reason.ChainMissing
	}
	origin := c[0]

	// 3. The origin.
	if !slices.Contains(origins, origin.Svc) {
		return reason.BadOrigin
	}

	// 4. Signatures and links, stamp by stamp, then the receivers.
	for i, s := range c {
		if !signed(s, keyrings) {
			return reason.BadSignature
		}
		prev := ""
		if i > 0 {
			prev = c[i-1].Sig
		}
		if s.Prev != prev {
			return reason.BrokenLink
		}
	}
	for i, s := range c {
		if i+1 == len(c) {
			if s.Rcv != receiver {
				return reason.BindingMismatch
			}
		} else if !policy.AddressedTo(s.Rcv, c[i+1].Svc) {
			return reason.BindingMismatch
		}
	}

	// 5. The shared rid.
	want := origin.RID
	if rid != nil {
		want = *rid
	}
	for _, s := range c {
		if s.RID != want {
			return reason.RIDMismatch
		}
	}

	// 6. The session.
	for _, s := range c {
		if s.Sess != sess {
			return reason.SessionUnknown
		}
	}
	return reason.OK
}

// signed reports whether s's sig verifies under one of the keys keyrings give s's svc, looked up by its
// service's own name only. Any fault, from no key to a sig that is not 64 bytes, is false.
func signed(s stamp.Stamp, keyrings []policy.Keyring) bool {
	candidates := KeysFor(keyrings, s.Svc)
	if len(candidates) == 0 {
		return false
	}
	msg, err := s.SigningBytes()
	if err != nil {
		return false
	}
	sig, err := b64.Decode(s.Sig)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(candidates, func(key ed25519.PublicKey) bool { return keys.Verify(key, msg, sig) })
}

// Commitments runs checks 8 and 9 on last, the chain's last stamp, and answers with the first that fails:
//
//  8. BINDING_MISMATCH unless last's bind is expectedBind; a nil expectedBind never matches;
//  9. INFLUENCE_MISMATCH unless the influence reads from influenceTok, its token, and last's infl is its
//     commitment. A nil influenceTok is the empty list, whose commitment is ""; an empty token is not
//     absent, and does not read.
//
// It answers OK when both hold.
func Commitments(last stamp.Stamp, expectedBind, influenceTok *string) reason.Code {
	// 8. The binding.
	if expectedBind == nil || last.Bind != *expectedBind {
		return reason.BindingMismatch
	}

	// 9. The influence commitment.
	var es []influence.Entry
	if influenceTok != nil {
		var err error
		if es, err = influence.ReadEntries(*influenceTok); err != nil {
			return reason.InfluenceMismatch
		}
	}
	committed, err := influence.Commit(es)
	if err != nil || last.Infl != committed {
		return reason.InfluenceMismatch
	}
	return reason.OK
}

// Route runs check 11: PATH_NOT_ALLOWED unless the proof read from proofTok, its token, proves the route
// against one of roots, the current ones, whose RootID is the proof's rootId. Only those are tried: the
// proof's rootId selects the tree, a root and its renewals sharing one, and a proof relabelled with
// another tree's rootId is checked against that tree. The route is the chain's own ([stamp.RouteOf]): its first
// svc, then each rcv, with an operation a hop names part of the route. A call's route ends at its receiver,
// which is the last rcv, while with inRoute false a response's ends at its last signer. A nil
// proofTok, or any fault in the proof, is not proven. It answers OK when the route is proven.
func Route(c stamp.Chain, inRoute bool, proofTok *string, roots []Root) reason.Code {
	if proofTok == nil {
		return reason.PathNotAllowed
	}
	p, err := policy.ReadProof(*proofTok)
	if err != nil {
		return reason.PathNotAllowed
	}
	route := stamp.RouteOf(c, inRoute)
	for _, root := range roots {
		if root.RootID == p.RootID && p.Verify(route, root.Bytes) {
			return reason.OK
		}
	}
	return reason.PathNotAllowed
}
