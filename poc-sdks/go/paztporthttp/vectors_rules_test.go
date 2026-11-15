// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestReceiverRulesVectors replays the receiver kinds of http-v4.json's rules: each case enters its request uses
// times at its service, under the case's extension settings, against one nonce cache already holding spent, and
// the last entry's answer is compared with expected: the refusal, whether the chain verified and the answer is
// attested, the items handed on, by name acted on, and, where the case asks them, whether a guarded public write
// to destinationOwner and a trusted record are allowed once the service has read the case's read.
func TestReceiverRulesVectors(t *testing.T) {
	refusals := map[string]bool{}
	writes := map[reason.Code]bool{}
	records := map[bool]bool{}
	for _, kind := range []string{"requests", "influenceItems", "servedUnverified", "attestation", "refusals",
		"trustedRecord"} {
		t.Run(kind, func(t *testing.T) {
			cases := vectors.Rules(t).Get(kind)
			if cases.Len() == 0 {
				t.Fatalf("the rules have no %s case", kind)
			}
			cases.Each(func(name string, c vectors.Node) {
				t.Run(name, func(t *testing.T) {
					c := c.With(t)
					a := runReceiverCase(t, c)
					got := answerOf(a)
					e := c.Get("expected")
					want := expectedAnswer(t, e)
					if got != want {
						t.Fatalf("got %s\nwant %s", got, want)
					}
					handover.Match(t, "handed on", a.HandOver, handover.Expected(t, e.Get("handedOn").Raw()))
					if a.HandOver != nil && a.HandOver.Verified() != a.Verified {
						t.Errorf("the hand-over's Verified is %v, the request's %v", a.HandOver.Verified(), a.Verified)
					}
					refusals[want.refusal] = true
					read := entries(c.Get("read"))
					if w := e.Get("publicWrite"); !w.IsNull() {
						owner := c.Get("destinationOwner").Str()
						if got := a.PublicWrite(read, owner); got != reason.Code(w.Str()) {
							t.Errorf("PublicWrite(%v, %q) = %s, want %s", read, owner, got, w.Str())
						}
						writes[reason.Code(w.Str())] = true
					}
					if r := e.Get("trustedRecord"); !r.IsNull() {
						if got := a.TrustedRecord(read); got != r.Bool() {
							t.Errorf("TrustedRecord(%v) = %v, want %v", read, got, r.Bool())
						}
						records[r.Bool()] = true
					}
				})
			})
		})
	}
	// The codes the version adds at a receiver: check 9a where it serves unverified, an item that does not read,
	// and a last block requiring what the service does not act on, refused in enforce mode.
	for _, want := range []string{`400 {"reason":"EXTENSION_MISMATCH"}`, `400 {"reason":"INFLUENCE_MISMATCH"}`,
		`403 {"reason":"EXTENSION_REQUIRED"}`} {
		if !refusals[want] {
			t.Errorf("no receiver case is refused %s", want)
		}
	}
	// The write rules deny as well as allow, and a trusted record is refused as well as granted.
	for _, want := range []reason.Code{reason.OK, reason.InfluenceDenied} {
		if !writes[want] {
			t.Errorf("no receiver case's public write is %s", want)
		}
	}
	if !records[true] || !records[false] {
		t.Errorf("the receiver cases' trusted records are %v; want both granted and refused", records)
	}
}

// TestUnsafeEndpointsVectors replays the rules' unsafeEndpoints: whether an endpoint is switched off
// for unsafe sessions, a HEAD wherever its GET is.
func TestUnsafeEndpointsVectors(t *testing.T) {
	cases := vectors.Rules(t).Get("unsafeEndpoints")
	if cases.Len() == 0 {
		t.Fatal("the rules have no unsafeEndpoints case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			disabled := paztporthttp.UnsafeEndpoints(c.Get("disabled").Strs())
			got := disabled.Refuses(c.Get("method").Str(), c.Get("routePattern").Str())
			if want := c.Get("refused").Bool(); got != want {
				t.Fatalf("Refuses = %v, want %v", got, want)
			}
		})
	})
}

// answer is a receiver case's answer, in the shape of its expected, but for what is handed on, which
// handover.Match compares.
type answer struct {
	refusal  string // "<status> <body>", or "null" for none
	verified bool
	attests  bool
}

func (a answer) String() string {
	return fmt.Sprintf("{refusal: %s, verified: %v, attests: %v}", a.refusal, a.verified, a.attests)
}

// answerOf returns a's answer.
func answerOf(a paztporthttp.Accepted) answer {
	r := "null"
	if a.Refusal != nil {
		r = fmt.Sprintf("%d %s", a.Refusal.Status, a.Refusal.Body)
	}
	return answer{refusal: r, verified: a.Verified, attests: a.Attests()}
}

// expectedAnswer reads a receiver case's expected.
func expectedAnswer(t testing.TB, e vectors.Node) answer {
	t.Helper()
	want := answer{refusal: "null", verified: e.Get("verified").Bool(), attests: e.Get("attests").Bool()}
	if r := e.Get("refusal"); !r.IsNull() {
		body, err := hex.DecodeString(r.Get("body").Str())
		if err != nil {
			t.Fatalf("the refusal's body: %v", err)
		}
		want.refusal = fmt.Sprintf("%d %s", r.Get("status").Int(), body)
	}
	return want
}

// runReceiverCase runs receiver case c and returns its last entry's Accepted. A case with no request is work
// outside any request: the zero Accepted.
func runReceiverCase(t *testing.T, c vectors.Node) paztporthttp.Accepted {
	t.Helper()
	r := caseReceiver(t, c)
	if c.Get("request").IsNull() {
		return paztporthttp.Accepted{}
	}
	req := caseRequest(t, c.Get("request"))
	peer := casePeer(c.Get("peer"))
	mode := caseMode(t, c.Get("mode"))
	uses := c.Get("uses").Int()
	if uses < 1 {
		t.Fatalf("the case runs %d times", uses)
	}
	var a paztporthttp.Accepted
	for range uses {
		a = r.Accept(t.Context(), req, peer, mode)
	}
	return a
}

// caseReceiver returns the receiver case c names: its service, with a stamper holding the service's
// key and a clock fixed at now, the case's extension settings, and, when it has a verifier, one pinned to its
// material under those settings.
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
		Extensions: caseSettings(t, c),
	}
	if s.Get("verifier").Bool() {
		r.Verifier = caseVerifier(t, c)
	}
	return r
}

// caseVerifier returns a verifier pinned to case c's material, in no session, under its extension settings,
// over a nonce cache that already holds the case's spent keys.
func caseVerifier(t *testing.T, c vectors.Node) *verify.Verifier {
	t.Helper()
	return caseVerifierWith(t, c, caseSettings(t, c))
}

// caseVerifierWith returns caseVerifier's verifier under the extension settings ext in place of the case's.
func caseVerifierWith(t *testing.T, c vectors.Node, ext verify.Extensions) *verify.Verifier {
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
		Extensions:     ext,
	})
}

// caseSettings returns case c's extension settings.
func caseSettings(t testing.TB, c vectors.Node) verify.Extensions {
	t.Helper()
	return handover.Settings(t, c.Get("actsOn").Raw(), c.Get("allowedExtensions").Raw())
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

// blocksOf returns the array of blocks n holds, read by the SDK's own reader from its canonical text.
func blocksOf(t testing.TB, n vectors.Node) stamp.Blocks {
	t.Helper()
	bs, err := stamp.ParseBlocks(canonical(t, n))
	if err != nil {
		t.Fatalf("the blocks: %v", err)
	}
	return bs
}

// blockOf returns the block n holds, read by the SDK's own reader from its canonical text.
func blockOf(t testing.TB, n vectors.Node) stamp.Block {
	t.Helper()
	b, err := stamp.ParseBlock(canonical(t, n))
	if err != nil {
		t.Fatalf("the block: %v", err)
	}
	return b
}

// canonical returns the canonical text of the value n holds.
func canonical(t testing.TB, n vectors.Node) []byte {
	t.Helper()
	v, err := json.ReadFile(n.Raw())
	if err != nil {
		t.Fatalf("the vector's text: %v", err)
	}
	b, err := json.Wire(v)
	if err != nil {
		t.Fatalf("the vector's value has no canonical text: %v", err)
	}
	return b
}
