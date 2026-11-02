// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// live are the codes a live verifier gives.
var live = []reason.Code{
	reason.OK, reason.ChainMissing, reason.BadOrigin, reason.BadSignature, reason.BrokenLink, reason.Expired,
	reason.RIDMismatch, reason.BindingMismatch, reason.Replay, reason.PathNotAllowed, reason.SessionUnknown,
	reason.InfluenceMismatch, reason.PeerMismatch, reason.PolicyExpired,
}

// FuzzVerify verifies any chain, influence and proof tokens, against a verifier that holds every key of
// v3.json's verify cases and the mesh policy, so that the "http hops ok" seed verifies. It never panics
// or fails, gives a live code other than POLICY_EXPIRED or PEER_MISMATCH (there is no peer), and names no
// one unless the result is OK or PATH_NOT_ALLOWED.
func FuzzVerify(f *testing.F) {
	v3 := vectors.Load(f, "v3.json")
	mesh := v3.Get("policies").Get("mesh")
	proof := mesh.Get("proofTokens").Get("gateway/orders/payment").Str()
	v3.Get("verify").Each(func(_ string, c vectors.Node) {
		f.Add(c.Get("chainToken").Str(), c.Get("influenceToken").Str(), proof)
	})
	root, err := b64.Decode(mesh.Get("root").Str())
	if err != nil {
		f.Fatal(err)
	}
	keyring := policy.Keyring{}
	for _, name := range []string{"session", "pi", "mcp-entry", "github-tools", "gateway", "orders"} {
		_, keyring[name] = vectors.V3Key(f, name)
	}
	rootID := mesh.Get("rootId").Str()
	const now = 1767225600000
	f.Fuzz(func(t *testing.T, chain, influence, proof string) {
		v := verify.New(verify.Config{
			Keyring:        keyring,
			Root:           root,
			RootID:         rootID,
			PolicyNotAfter: 4102444800000,
			AllowedOrigins: []string{"session", "gateway", "mcp-entry"},
			Sess:           "sess-2",
			Nonces:         verify.NewMemoryNonceCache(verify.NonceTTLMs),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   verify.CallMaxAgeMs,
			RunMaxAgeMs:    verify.RunMaxAgeMs,
		})
		bind, key := "bind-orders-to-payment", "rid-2|orders|req"
		r, err := v.Verify(t.Context(), verify.Input{
			Chain:           &chain,
			ExpectedBind:    &bind,
			Influence:       &influence,
			Proof:           &proof,
			Receiver:        "payment",
			ReceiverInRoute: true,
			NonceKey:        &key,
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}
		known := false
		for _, code := range live {
			known = known || r.Reason == code
		}
		if !known || r.Reason == reason.PolicyExpired || r.Reason == reason.PeerMismatch {
			t.Fatalf("Verify gave %q", r.Reason)
		}
		named := r.SuspectSvc != "" || r.SuspectInst != ""
		if named && r.Reason != reason.OK && r.Reason != reason.PathNotAllowed {
			t.Fatalf("a %s result names %q, %q", r.Reason, r.SuspectSvc, r.SuspectInst)
		}
	})
}
