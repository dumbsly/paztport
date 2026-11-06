// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestReceiverRulesVectors replays the receiver kinds of http-v3.json's rules: each case enters its
// request uses times at its service, against one nonce cache already holding spent, the handler then
// reads read, and the last entry's answer is compared with expected.
func TestReceiverRulesVectors(t *testing.T) {
	for _, kind := range []string{"requests", "unreadableInfluence", "attestation", "refusals", "trustedRecord"} {
		t.Run(kind, func(t *testing.T) {
			cases := vectors.Rules(t).Get(kind)
			if cases.Len() == 0 {
				t.Fatalf("the rules have no %s case", kind)
			}
			cases.Each(func(name string, c vectors.Node) {
				t.Run(name, func(t *testing.T) {
					c := c.With(t)
					got := runReceiverCase(t, c)
					want := expectedAnswer(t, c.Get("expected"))
					if !got.equal(want) {
						t.Fatalf("got %s\nwant %s", got, want)
					}
				})
			})
		})
	}
}

// TestUnsafeOperationsVectors replays the rules' unsafeOperations: whether an operation is switched off
// for unsafe sessions, a HEAD wherever its GET is.
func TestUnsafeOperationsVectors(t *testing.T) {
	cases := vectors.Rules(t).Get("unsafeOperations")
	if cases.Len() == 0 {
		t.Fatal("the rules have no unsafeOperations case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			disabled := paztporthttp.UnsafeOperations(c.Get("disabled").Strs())
			got := disabled.Refuses(c.Get("method").Str(), c.Get("routePattern").Str())
			if want := c.Get("refused").Bool(); got != want {
				t.Fatalf("Refuses = %v, want %v", got, want)
			}
		})
	})
}

// answer is a receiver case's answer, in the shape of its expected.
type answer struct {
	refusal  *paztporthttp.Answer
	verified bool
	infl     []influence.Entry
	attests  bool
	trusted  bool
}

func (a answer) equal(b answer) bool {
	sameRefusal := (a.refusal == nil) == (b.refusal == nil)
	if sameRefusal && a.refusal != nil {
		sameRefusal = a.refusal.Status == b.refusal.Status && string(a.refusal.Body) == string(b.refusal.Body)
	}
	return sameRefusal && a.verified == b.verified && slices.Equal(a.infl, b.infl) &&
		a.attests == b.attests && a.trusted == b.trusted
}

func (a answer) String() string {
	r := "null"
	if a.refusal != nil {
		r = fmt.Sprintf("%d %s", a.refusal.Status, a.refusal.Body)
	}
	return fmt.Sprintf("{refusal: %s, verified: %v, influence: %+v, attests: %v, trustedRecord: %v}",
		r, a.verified, a.infl, a.attests, a.trusted)
}

// expectedAnswer reads a receiver case's expected.
func expectedAnswer(t testing.TB, e vectors.Node) answer {
	t.Helper()
	want := answer{
		verified: e.Get("verified").Bool(),
		infl:     entries(e.Get("influence")),
		attests:  e.Get("attests").Bool(),
		trusted:  e.Get("trustedRecord").Bool(),
	}
	if r := e.Get("refusal"); !r.IsNull() {
		body, err := hex.DecodeString(r.Get("body").Str())
		if err != nil {
			t.Fatalf("the refusal's body: %v", err)
		}
		want.refusal = &paztporthttp.Answer{Status: int(r.Get("status").Int()), Body: body}
	}
	return want
}

// runReceiverCase runs receiver case c and answers in the shape of its expected. A case with no request
// is work outside any request, which only TrustedRecord is asked about, of the zero Accepted.
func runReceiverCase(t *testing.T, c vectors.Node) answer {
	t.Helper()
	read := entries(c.Get("read"))
	r := caseReceiver(t, c)
	if c.Get("request").IsNull() {
		return answer{trusted: paztporthttp.Accepted{}.TrustedRecord(read)}
	}
	req := caseRequest(t, c.Get("request"))
	peer := casePeer(c.Get("peer"))
	mode := caseMode(t, c.Get("mode"))
	uses := c.Get("uses").Int()
	if uses < 1 {
		t.Fatalf("the case runs %d times", uses)
	}
	var a paztporthttp.Accepted
	var trusted bool
	for range uses {
		a = r.Accept(t.Context(), req, peer, mode)
		var readNow []influence.Entry
		if a.Refusal == nil {
			readNow = read
		}
		trusted = a.TrustedRecord(readNow)
	}
	return answer{refusal: a.Refusal, verified: a.Verified, infl: a.Influence, attests: a.Attests(), trusted: trusted}
}

// caseReceiver returns the receiver case c names: its service, with a stamper holding the service's
// key and a clock fixed at now, and, when it has a verifier, one pinned to its material.
func caseReceiver(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
	t.Helper()
	s := c.Get("service")
	svc := s.Get("svc").Str()
	origin := s.Get("origin").Bool()
	now := c.Get("now").Int()
	priv, _ := vectors.RulesKey(t, svc)
	r := &paztporthttp.Receiver{
		Name:   svc,
		Origin: origin,
		Stamper: &stamp.Stamper{
			Svc: svc, Inst: s.Get("inst").Str(), Key: priv, Origin: origin,
			NewRID: func() string { return "unused" }, Now: func() int64 { return now },
		},
	}
	if s.Get("verifier").Bool() {
		r.Verifier = caseVerifier(t, c)
	}
	return r
}

// caseVerifier returns a verifier pinned to case c's material, in no session, over a nonce cache that
// already holds the case's spent keys.
func caseVerifier(t *testing.T, c vectors.Node) *verify.Verifier {
	t.Helper()
	now := c.Get("now").Int()
	nonces := verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int())
	for _, k := range c.Get("spent").Strs() {
		if _, err := nonces.SeenBefore(t.Context(), k, now); err != nil {
			t.Fatalf("SeenBefore: %v", err)
		}
	}
	return pinnedVerifier(t, c.Get("material").Str(), verify.Config{
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Nonces:         nonces,
		Now:            func() int64 { return now },
		CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
		RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
	})
}

// pinnedVerifier returns a verifier for cfg pinned to the rules' material called material, read from
// its files' text by the SDK's own readers.
func pinnedVerifier(t testing.TB, material string, cfg verify.Config) *verify.Verifier {
	t.Helper()
	m := vectors.RulesMaterial(t, material)
	kf, err := policy.ParseKeyringFile(m.Keyring)
	if err != nil {
		t.Fatalf("ParseKeyringFile: %v", err)
	}
	root, err := policy.ParseRootFile(m.Root)
	if err != nil {
		t.Fatalf("ParseRootFile: %v", err)
	}
	_, pub := vectors.RulesKey(t, m.PolicyKey)
	cfg, err = verify.Pinned([]policy.KeyringFile{kf}, []policy.Root{root}, keys.EncodePublic(pub), cfg)
	if err != nil {
		t.Fatalf("Pinned: %v", err)
	}
	return verify.New(cfg)
}

// caseRequest returns the request n describes, its headers looked up by name in any case.
func caseRequest(t testing.TB, n vectors.Node) paztporthttp.InboundRequest {
	t.Helper()
	headers := n.Get("headers")
	lookup := func(name string) []string {
		var vs []string
		for _, h := range headers.Names() {
			if strings.EqualFold(h, name) {
				vs = append(vs, headers.Get(h).Str())
			}
		}
		return vs
	}
	body, err := hex.DecodeString(n.Get("body").Str())
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return paztporthttp.NewInboundRequest(n.Get("method").Str(), n.Get("target").Str(), body, lookup)
}

// casePeer returns the peer n describes, or nil for none.
func casePeer(n vectors.Node) *verify.Peer {
	if n.IsNull() {
		return nil
	}
	return &verify.Peer{Svc: n.Get("svc").Str(), Inst: n.Get("inst").Str()}
}

// caseMode returns the mode n names: enforce, audit, off, or null for a service that verifies no
// requests.
func caseMode(t testing.TB, n vectors.Node) paztporthttp.Mode {
	t.Helper()
	if n.IsNull() {
		return paztporthttp.ModeNone
	}
	switch s := n.Str(); s {
	case "enforce", "audit", "off":
		return paztporthttp.ParseMode(s)
	default:
		t.Fatalf("the case's mode %q is none the rules name", s)
		return 0
	}
}

// entries returns the entries array n describes.
func entries(n vectors.Node) []influence.Entry {
	es := make([]influence.Entry, n.Len())
	for i := range es {
		e := n.Index(i)
		es[i] = influence.Entry{Class: influence.Class(e.Get("cls").Str()), Src: e.Get("src").Str(), H: e.Get("h").Str()}
		if e.Has("cid") {
			es[i].CID, es[i].HasCID = e.Get("cid").Str(), true
		}
		if e.Has("owner") {
			es[i].Owner = e.Get("owner").Str()
		}
	}
	return es
}
