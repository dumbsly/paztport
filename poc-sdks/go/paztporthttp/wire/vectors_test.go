// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"bytes"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestRequestBindingVectors replays http-v4.json's request bindings: a method, a target exactly as sent
// and a body give the binding.
func TestRequestBindingVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v4.json").Get("requestBinding")
	if cases.Len() != 6 {
		t.Fatalf("http-v4.json has %d requestBinding cases, want 6", cases.Len())
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

// TestHeaderNameVectors replays http-v4.json's header names: a header name is Paztport's when it begins
// with X-Path-, compared case-insensitively over ASCII, so version 3's X-Path-Influence is Paztport's as much as
// X-Path-Extensions is.
func TestHeaderNameVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v4.json").Get("headerNames")
	if cases.Len() != 16 {
		t.Fatalf("http-v4.json has %d headerNames cases, want 16", cases.Len())
	}
	paztport := map[string]bool{}
	cases.Each(func(_ string, c vectors.Node) {
		if c.Get("paztport").Bool() {
			paztport[c.Get("header").Str()] = true
		}
	})
	if !paztport[wire.Extensions] || !paztport["X-Path-Influence"] {
		t.Fatalf("http-v4.json does not give both %s and X-Path-Influence as Paztport's", wire.Extensions)
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

// TestResultHashVectors replays http-v4.json's result hashes: a status and a body give the hash.
func TestResultHashVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v4.json").Get("resultHash")
	if cases.Len() != 4 {
		t.Fatalf("http-v4.json has %d resultHash cases, want 4", cases.Len())
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

// TestResponseVectors replays http-v4.json's responses: the caller checks the header payment returned
// against the chain and blocks it sent, the status and the body, with the proof it sent and the case's extension
// settings, uses times against one nonce cache that already holds the case's spent keys, and expects the last
// check, its hand-over included. Each case runs under its own policyNotAfter.
func TestResponseVectors(t *testing.T) {
	cases := vectors.Load(t, "http-v4.json").Get("responses")
	if cases.Len() != 19 {
		t.Fatalf("http-v4.json has %d responses cases, want 19", cases.Len())
	}
	// The codes the section exists for, from its data, so that a filtered run still checks they occur.
	occur := map[reason.Code]bool{}
	cases.Each(func(_ string, c vectors.Node) { occur[reason.Code(c.Get("expected").Get("reason").Str())] = true })
	for _, code := range []reason.Code{
		reason.OK, reason.BindingMismatch, reason.ExtensionMismatch, reason.Replay, reason.PolicyExpired,
		reason.ChainMissing, reason.ExtensionRequired,
	} {
		if !occur[code] {
			t.Fatalf("no responses case expects %s", code)
		}
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
				got, err = wire.CheckResponse(t.Context(), v, rc.sent, rc.sentBlocks, &rc.proof, rc.header, rc.status,
					rc.body, rc.caller, rc.key)
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
			if plain(got.Result) != want {
				t.Errorf("Result = %+v, want %+v", plain(got.Result), want)
			}
			handover.Match(t, "the response's hand-over", got.Result.HandOver, handover.Expected(t, e.Get("handOver").Raw()))
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
	cfg        verify.Config
	nonceTTL   int64
	sent       stamp.Chain
	sentBlocks stamp.Blocks
	proof      policy.Proof
	header     string
	status     int
	body       []byte
	caller     string
	key        string
}

// responseMaterial returns the root (base64url), root id and proof a responses case runs on: those of the
// rules material it names, or of the v4.json policy it names.
func responseMaterial(t testing.TB, c vectors.Node) (root, rootID string, proof policy.Proof) {
	t.Helper()
	var err error
	if c.Has("material") {
		m := vectors.Rules(t).Get("material").Get(c.Get("material").Str())
		// The material's proofs are in the file's own text, which the bundle reader takes.
		file := bytes.Join([][]byte{
			[]byte(`{"service":"gateway","rootId":`), m.Get("root").Get("rootId").Raw(),
			[]byte(`,"proofs":`), m.Get("proofs").Raw(), []byte(`}`),
		}, nil)
		bundle, berr := policy.ParseProofBundleFile(file)
		if berr != nil {
			t.Fatalf("ParseProofBundleFile: %v", berr)
		}
		var ok bool
		if proof, ok = bundle.ProofFor(c.Get("proofRoute").Str()); !ok {
			t.Fatalf("the material has no proof for %s", c.Get("proofRoute").Str())
		}
		return m.Get("root").Get("root").Str(), m.Get("root").Get("rootId").Str(), proof
	}
	p := vectors.Load(t, "v4.json").Get("policies").Get(c.Get("policy").Str())
	proof, err = policy.ReadProof(p.Get("proofTokens").Get(c.Get("proofRoute").Str()).Str())
	if err != nil {
		t.Fatalf("the proof: %v", err)
	}
	return p.Get("root").Str(), p.Get("rootId").Str(), proof
}

// readResponseCase reads responses case c, with a clock fixed at its now. A case with spent keys gets a
// nonce cache that already holds them; any other gets none, so verifier gives it a fresh one.
func readResponseCase(t testing.TB, c vectors.Node) responseCase {
	t.Helper()
	c = c.With(t)
	rootText, rootID, proof := responseMaterial(t, c)
	root, err := b64.Decode(rootText)
	if err != nil {
		t.Fatalf("the policy's root: %v", err)
	}
	keyring := policy.Keyring{}
	ring := c.Get("keyring")
	for _, svc := range ring.Names() {
		_, pub := vectors.VectorKey(t, ring.Get(svc).Str())
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
		if v := s.Get("v").Int(); v != 4 {
			t.Fatalf("sent stamp %d has v %d", i, v)
		}
		sent[i] = stamp.Stamp{
			Svc: s.Get("svc").Str(), Inst: s.Get("inst").Str(), RID: s.Get("rid").Str(), TS: s.Get("ts").Int(),
			Sess: s.Get("sess").Str(), Rcv: s.Get("rcv").Str(), Bind: s.Get("bind").Str(),
			Ext: s.Get("ext").Str(), Prev: s.Get("prev").Str(), Sig: s.Get("sig").Str(),
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
			Roots:          []verify.PinnedRoot{{Root: root, RootID: rootID, NotAfter: policyNotAfter}},
			PolicyNotAfter: policyNotAfter,
			AllowedOrigins: allowed,
			Sess:           c.Get("sess").Str(),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
			Nonces:         nonces,
			Extensions:     extensions(t, c),
		},
		nonceTTL:   c.Get("nonceTtlMs").Int(),
		sent:       sent,
		sentBlocks: blocks(t, c.Get("sentBlocks")),
		proof:      proof,
		header:     c.Get("responseHeader").Str(),
		status:     int(c.Get("status").Int()),
		body:       c.Get("body").With(t).Hex(),
		caller:     c.Get("caller").Str(),
		key:        responseKey(c),
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

// extensions returns the settings case c gives: acting on actsOn and carrying any name, or, where
// allowedExtensions is not null, only the names it lists.
func extensions(t testing.TB, c vectors.Node) verify.Extensions {
	t.Helper()
	var e verify.Extensions
	var err error
	if allowed := c.Get("allowedExtensions"); allowed.IsNull() {
		e, err = verify.NewExtensions(c.Get("actsOn").Strs())
	} else {
		e, err = verify.NewExtensionsAllowing(c.Get("actsOn").Strs(), allowed.Strs())
	}
	if err != nil {
		t.Fatalf("the case's extension settings: %v", err)
	}
	return e
}

// blocks returns the blocks array n holds, read by the SDK's own reader from its canonical text.
func blocks(t testing.TB, n vectors.Node) stamp.Blocks {
	t.Helper()
	v, err := json.ReadFile(n.Raw())
	if err != nil {
		t.Fatalf("the blocks: %v", err)
	}
	b, err := json.Wire(v)
	if err != nil {
		t.Fatalf("the blocks have no canonical text: %v", err)
	}
	bs, err := stamp.ParseBlocks(b)
	if err != nil {
		t.Fatalf("the blocks: %v", err)
	}
	return bs
}

// responseKey returns the key value the case's call gave, "" when it gave none.
func responseKey(c vectors.Node) string {
	if c.Has("key") {
		return c.Get("key").Str()
	}
	return ""
}
