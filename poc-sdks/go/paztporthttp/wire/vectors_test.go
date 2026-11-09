// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestRequestBindingVectors replays http-v3.json's request bindings: a method, a target exactly as sent
// and a body give the binding.
func TestRequestBindingVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v3.json").Get("requestBinding")
	if cases.Len() == 0 {
		t.Fatal("http-v3.json has no requestBinding case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			got, err := wire.Bind(c.Get("method").Str(), c.Get("target").Str(), c.Get("body").With(t).Hex())
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if want := c.Get("bind").Str(); got != want {
				t.Fatalf("Bind = %s, want %s", got, want)
			}
		})
	})
}

// TestHeaderNameVectors replays http-v3.json's header names: a header name is Paztport's when it begins
// with X-Path-, compared case-insensitively over ASCII.
func TestHeaderNameVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v3.json").Get("headerNames")
	if cases.Len() == 0 {
		t.Fatal("http-v3.json has no headerNames case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			header := c.Get("header").Str()
			if got, want := wire.IsPaztport(header), c.Get("paztport").Bool(); got != want {
				t.Fatalf("IsPaztport(%q) = %t, want %t", header, got, want)
			}
		})
	})
}

// TestResultHashVectors replays http-v3.json's result hashes: a status and a body give the hash.
func TestResultHashVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v3.json").Get("resultHash")
	if cases.Len() == 0 {
		t.Fatal("http-v3.json has no resultHash case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			got := wire.ResultHash(int(c.Get("status").Int()), c.Get("body").With(t).Hex())
			if want := c.Get("hash").Str(); got != want {
				t.Fatalf("ResultHash = %s, want %s", got, want)
			}
		})
	})
}

// TestResponseVectors replays http-v3.json's responses: the caller checks the header payment returned
// against the chain it sent, the status and the body, with the proof it sent, uses times against one
// nonce cache that already holds the case's spent keys, and expects the last check. Each case runs under
// its own policyNotAfter.
func TestResponseVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v3.json").Get("responses")
	if cases.Len() == 0 {
		t.Fatal("http-v3.json has no responses case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			rc := readResponseCase(t, c)
			uses := c.With(t).Get("uses").Int()
			if uses < 1 {
				t.Fatalf("the case runs %d times", uses)
			}
			v := rc.verifier()
			var got wire.ResponseCheck
			for range uses {
				var err error
				got, err = wire.CheckResponse(t.Context(), v, rc.sent, &rc.proof, rc.header, rc.status, rc.body,
					rc.caller)
				if err != nil {
					t.Fatalf("CheckResponse: %v", err)
				}
			}
			e := c.With(t).Get("expected")
			want := verify.Result{
				Reason:      reason.Code(e.Get("reason").Str()),
				SuspectSvc:  e.Get("suspectSvc").Str(),
				SuspectInst: e.Get("suspectInst").Str(),
			}
			if got.Result != want {
				t.Errorf("Result = %+v, want %+v", got.Result, want)
			}
			if wantLabels := labels(e.Get("labels")); !slices.Equal(got.Labels, wantLabels) {
				t.Errorf("Labels = %+v, want %+v", got.Labels, wantLabels)
			}
			if wantHash := e.Get("resultHash").Str(); got.ResultHash != wantHash {
				t.Errorf("ResultHash = %s, want %s", got.ResultHash, wantHash)
			}
		})
	})
}

// TestHTTPBindingRefusals replays json.json's HTTP bindings, each a method or target with a lone
// surrogate. The harness hands it over as the Go string that stands for it, which is not valid UTF-8, so
// the request has no binding.
func TestHTTPBindingRefusals(t *testing.T) {
	found := 0
	vectors.Load(t, "json.json").Get("bindings").Each(func(name string, c vectors.Node) {
		if c.Get("binding").Str() != "http" {
			return
		}
		found++
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if !c.Get("expected").IsNull() {
				t.Fatal("the case expects a binding; only refusals are replayed here")
			}
			in := c.Get("inputs")
			if got, err := wire.Bind(in.Get("method").Str(), in.Get("target").Str(), in.Get("body").With(t).Hex()); err == nil {
				t.Fatalf("Bind bound it as %s", got)
			}
		})
	})
	if found == 0 {
		t.Fatal("json.json has no http binding case")
	}
}

// responseCase is one responses case, read: the verifier's Config and what the caller passes to
// CheckResponse. A Config with no nonce cache is given a fresh one of nonceTTL by verifier.
type responseCase struct {
	cfg      verify.Config
	nonceTTL int64
	sent     stamp.Chain
	proof    policy.Proof
	header   string
	status   int
	body     []byte
	caller   string
}

// readResponseCase reads responses case c, with a clock fixed at its now. A case with spent keys gets a
// nonce cache that already holds them; any other gets none, so verifier gives it a fresh one.
func readResponseCase(t testing.TB, c vectors.Node) responseCase {
	t.Helper()
	c = c.With(t)
	p := vectors.Load(t, "v3.json").Get("policies").Get(c.Get("policy").Str())
	root, err := b64.Decode(p.Get("root").Str())
	if err != nil {
		t.Fatalf("the policy's root: %v", err)
	}
	proof, err := policy.ReadProof(p.Get("proofTokens").Get(c.Get("proofRoute").Str()).Str())
	if err != nil {
		t.Fatalf("the proof: %v", err)
	}
	keyring := policy.Keyring{}
	ring := c.Get("keyring")
	for _, svc := range ring.Names() {
		_, pub := vectors.V3Key(t, ring.Get(svc).Str())
		keyring[svc] = pub
	}
	origins := c.Get("allowedOrigins")
	allowed := make([]string, origins.Len())
	for i := range allowed {
		allowed[i] = origins.Index(i).Str()
	}
	now, policyNotAfter := c.Get("now").Int(), c.Get("policyNotAfter").Int()
	sentNode := c.Get("sent")
	sent := make(stamp.Chain, sentNode.Len())
	for i := range sent {
		s := sentNode.Index(i)
		if v := s.Get("v").Int(); v != 3 {
			t.Fatalf("sent stamp %d has v %d", i, v)
		}
		sent[i] = stamp.Stamp{
			Svc: s.Get("svc").Str(), Inst: s.Get("inst").Str(), RID: s.Get("rid").Str(), TS: s.Get("ts").Int(),
			Sess: s.Get("sess").Str(), Rcv: s.Get("rcv").Str(), Bind: s.Get("bind").Str(),
			Infl: s.Get("infl").Str(), Prev: s.Get("prev").Str(), Sig: s.Get("sig").Str(),
		}
	}
	var nonces verify.NonceCache
	if c.Has("spent") {
		cache := verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int())
		for _, k := range c.Get("spent").Strs() {
			if _, err := cache.SeenBefore(t.Context(), k, now); err != nil {
				t.Fatalf("SeenBefore: %v", err)
			}
		}
		nonces = cache
	}
	return responseCase{
		cfg: verify.Config{
			// The case gives one window, its policyNotAfter, so each member has that one.
			Keyrings:       []verify.PinnedKeyring{{Keys: keyring, NotAfter: policyNotAfter}},
			Roots:          []verify.PinnedRoot{{Root: root, RootID: p.Get("rootId").Str(), NotAfter: policyNotAfter}},
			PolicyNotAfter: policyNotAfter,
			AllowedOrigins: allowed,
			Sess:           c.Get("sess").Str(),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
			Nonces:         nonces,
		},
		nonceTTL: c.Get("nonceTtlMs").Int(),
		sent:     sent,
		proof:    proof,
		header:   c.Get("responseHeader").Str(),
		status:   int(c.Get("status").Int()),
		body:     c.Get("body").With(t).Hex(),
		caller:   c.Get("caller").Str(),
	}
}

// verifier returns a verifier for rc's Config, with a fresh nonce cache unless the Config has one.
func (rc responseCase) verifier() *verify.Verifier {
	cfg := rc.cfg
	if cfg.Nonces == nil {
		cfg.Nonces = verify.NewMemoryNonceCache(rc.nonceTTL)
	}
	return verify.New(cfg)
}

// labels returns the labels array n describes.
func labels(n vectors.Node) []influence.Label {
	ls := make([]influence.Label, n.Len())
	for i := range ls {
		l := n.Index(i)
		ls[i] = influence.Label{Class: influence.Class(l.Get("cls").Str()), CID: l.Get("cid").Str()}
		if l.Has("owner") {
			ls[i].Owner = l.Get("owner").Str()
		}
	}
	return ls
}
