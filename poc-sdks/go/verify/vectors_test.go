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

// TestVectors replays v3.json's verify cases. Each builds its Config directly, with a fixed clock and a
// fresh MemoryNonceCache of the case's nonceTtlMs, runs the verifier uses times against that one cache,
// and expects the last result. A case reads only its tokens, never the readable values beside them.
func TestVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	cases := v3.Get("verify")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no verify case")
	}
	policies := v3.Get("policies")
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			p := policies.With(t).Get(c.Get("policy").Str())
			root, err := b64.Decode(p.Get("root").Str())
			if err != nil {
				t.Fatalf("the policy's root: %v", err)
			}
			keyring := policy.Keyring{}
			ring := c.Get("keyring")
			for _, svc := range ring.Names() {
				_, pub := vectors.V3Key(t, ring.Get(svc).Str())
				keyring[svc] = pub
			}
			now := c.Get("now").Int()
			cfg := verify.Config{
				Keyring:        keyring,
				Root:           root,
				RootID:         p.Get("rootId").Str(),
				PolicyNotAfter: c.Get("policyNotAfter").Int(),
				AllowedOrigins: strs(c.Get("allowedOrigins")),
				Sess:           c.Get("sess").Str(),
				Nonces:         verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int()),
				Now:            func() int64 { return now },
				CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
				RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
			}
			in := verify.Input{
				Chain:           optional(c.Get("chainToken")),
				ExpectedBind:    optional(c.Get("expectedBind")),
				Influence:       optional(c.Get("influenceToken")),
				Receiver:        c.Get("receiver").Str(),
				ReceiverInRoute: c.Get("receiverInRoute").Bool(),
				NonceKey:        optional(c.Get("nonceKey")),
			}
			if route := c.Get("proofRoute"); !route.IsNull() {
				tok := p.Get("proofTokens").Get(route.Str()).Str()
				in.Proof = &tok
			}
			if peer := c.Get("peer"); !peer.IsNull() {
				in.Peer = &verify.Peer{Svc: peer.Get("svc").Str(), Inst: peer.Get("inst").Str()}
			}
			uses := c.Get("uses").Int()
			if uses < 1 {
				t.Fatalf("the case runs %d times", uses)
			}
			v := verify.New(cfg)
			var got verify.Result
			for range uses {
				if got, err = v.Verify(t.Context(), in); err != nil {
					t.Fatalf("Verify: %v", err)
				}
			}
			e := c.Get("expected")
			want := verify.Result{
				Reason:      reason.Code(e.Get("reason").Str()),
				SuspectSvc:  e.Get("suspectSvc").Str(),
				SuspectInst: e.Get("suspectInst").Str(),
			}
			if got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
			if got.OK() != (want.Reason == reason.OK) {
				t.Fatalf("OK() = %t for %s", got.OK(), got.Reason)
			}
		})
	})
}

// optional returns n's string, or nil when n is null.
func optional(n vectors.Node) *string {
	if n.IsNull() {
		return nil
	}
	s := n.Str()
	return &s
}

// strs returns the strings of array n.
func strs(n vectors.Node) []string {
	out := make([]string, n.Len())
	for i := range out {
		out[i] = n.Index(i).Str()
	}
	return out
}
