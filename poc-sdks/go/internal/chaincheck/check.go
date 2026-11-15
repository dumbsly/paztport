// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Root is a pinned root as check 12 uses it: the bytes of the root of an allowed routes' tree, and the
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

// Stamps runs checks 2 to 6 of verification.md's live order on c, a chain the reader has read, and answers
// with the first that fails:
//
//  2. BAD_ORIGIN, unless the origin's svc is one of origins;
//  3. for each stamp in order, BAD_SIGNATURE unless some keyring of keyrings, the current ones, holds a
//     key under its svc and its sig verifies under one of the keys they give it, then BROKEN_LINK unless
//     its prev is "" at the origin and the previous stamp's sig otherwise;
//  4. only once every stamp has passed check 3, BINDING_MISMATCH unless each stamp's rcv addresses the next
//     stamp's svc, which is the svc itself or the svc, '#' and an operation name, and the last stamp's rcv is
//     receiver exactly;
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

	// 2. The origin.
	if !slices.Contains(origins, origin.Svc) {
		return reason.BadOrigin
	}

	// 3. Signatures and links, stamp by stamp.
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
	// 4. The receivers.
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

// Binding runs check 8 alone: BINDING_MISMATCH unless last's bind, the last stamp's, is expectedBind; a nil
// expectedBind never matches. It answers OK when it holds.
func Binding(last stamp.Stamp, expectedBind *string) reason.Code {
	if expectedBind == nil || last.Bind != *expectedBind {
		return reason.BindingMismatch
	}
	return reason.OK
}

// Match runs check 9a alone (verification.md, The live order): EXTENSION_MISMATCH unless the blocks read from
// tok, their token, as an array of blocks with one block per stamp of c, and each block's commitment is its
// stamp's ext, compared as text and never decoded. A nil tok, no token received, is one empty block per stamp;
// a token that reads as anything but an array of blocks, JSON null and an empty token among them, is refused,
// never taken for none. It answers with the blocks, one per stamp, and OK, or with no blocks and
// EXTENSION_MISMATCH. Both verifiers and a service serving a request it did not verify call it, so the rule is
// written once.
func Match(c stamp.Chain, tok *string) (stamp.Blocks, reason.Code) {
	bs := make(stamp.Blocks, len(c)) // each the zero Block, the empty block
	if tok != nil {
		read, err := stamp.ReadBlocks(*tok)
		if err != nil {
			return nil, reason.ExtensionMismatch
		}
		bs = read
	}
	if len(bs) != len(c) {
		return nil, reason.ExtensionMismatch
	}
	for i, b := range bs {
		if b.Commit() != c[i].Ext {
			return nil, reason.ExtensionMismatch
		}
	}
	return bs, reason.OK
}

// Blocks runs checks 9a, 9b, then 9c when live is true (verification.md, The live order), on c and the blocks
// token tok, and answers with the blocks and OK, or with no blocks and the first that fails:
//
//   - 9a: as Match;
//   - 9b: EXTENSION_NOT_ALLOWED unless every name in any block's items or requires is one carries holds;
//   - 9c: EXTENSION_REQUIRED unless every name in the last block's requires is one actsOn holds. Only the direct
//     caller's requires binds; offline, live is false, since a record does not hold the actsOn it was checked
//     against live.
//
// carries and actsOn are the service's extension settings, as predicates, since this package cannot name the
// verify package's type. 9a runs first, so every name 9b and 9c read is one its block's signer committed to.
func Blocks(c stamp.Chain, tok *string, carries, actsOn func(string) bool, live bool) (stamp.Blocks, reason.Code) {
	bs, code := Match(c, tok)
	if code != reason.OK {
		return nil, code
	}
	for _, b := range bs {
		if !all(b.Names(), carries) || !all(b.Requires(), carries) {
			return nil, reason.ExtensionNotAllowed
		}
	}
	if live && len(bs) > 0 && !all(bs[len(bs)-1].Requires(), actsOn) {
		return nil, reason.ExtensionRequired
	}
	return bs, reason.OK
}

// all reports whether every name in names is one holds.
func all(names []string, holds func(string) bool) bool {
	for _, n := range names {
		if !holds(n) {
			return false
		}
	}
	return true
}

// Route runs check 12: PATH_NOT_ALLOWED unless the proof read from proofTok, its token, proves the route
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
