// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Stamps runs checks 3 to 6 on c, a chain the reader has read, and answers with the first that fails:
//
//  3. BAD_ORIGIN, unless the origin's svc is one of origins;
//  4. for each stamp in order, BAD_SIGNATURE unless keyring holds a key under its svc and its sig verifies
//     under that key, then BROKEN_LINK unless its prev is "" at the origin and the previous stamp's sig
//     otherwise; only once every stamp has passed that, BINDING_MISMATCH unless each stamp's rcv is the
//     next stamp's svc and the last stamp's rcv is receiver;
//  5. RID_MISMATCH unless every stamp carries rid, or the origin's rid when rid is nil;
//  6. SESSION_UNKNOWN unless every stamp carries sess.
//
// It answers OK when all hold. Checking the receivers only after the signature loop means a forged chain
// is reported as forged, not as misdirected. An empty chain, which no reader returns, is CHAIN_MISSING.
func Stamps(c stamp.Chain, keyring policy.Keyring, origins []string, sess, receiver string, rid *string) reason.Code {
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
		if !signed(s, keyring) {
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
		next := receiver
		if i+1 < len(c) {
			next = c[i+1].Svc
		}
		if s.Rcv != next {
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

// signed reports whether s's sig verifies under the key keyring holds for s's svc. A key is looked up by
// its service's own name only. Any fault, from a missing key to a sig that is not 64 bytes, is false.
func signed(s stamp.Stamp, keyring policy.Keyring) bool {
	key, ok := keyring[s.Svc]
	if !ok {
		return false
	}
	msg, err := s.SigningBytes()
	if err != nil {
		return false
	}
	sig, err := b64.Decode(s.Sig)
	return err == nil && keys.Verify(key, msg, sig)
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

// Route runs check 11: PATH_NOT_ALLOWED unless the proof read from proofTok, its token, names rootID and
// proves the route against root, the bytes of the pinned root. The route is c's svc values in order,
// then receiver when inRoute: a call's route ends at its receiver, while a response's ends at its last
// signer. A nil proofTok, or any fault in the proof, is not proven. It answers OK when the route is
// proven.
func Route(c stamp.Chain, receiver string, inRoute bool, proofTok *string, root []byte, rootID string) reason.Code {
	if proofTok == nil {
		return reason.PathNotAllowed
	}
	p, err := policy.ReadProof(*proofTok)
	if err != nil || p.RootID != rootID {
		return reason.PathNotAllowed
	}
	nodes := make([]string, 0, len(c)+1)
	for _, s := range c {
		nodes = append(nodes, s.Svc)
	}
	if inRoute {
		nodes = append(nodes, receiver)
	}
	if !p.Verify(policy.JoinRoute(nodes...), root) {
		return reason.PathNotAllowed
	}
	return reason.OK
}
