// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// nbsp is U+00A0, a no-break space, as its UTF-8 bytes: whitespace to Go's strings.TrimSpace, but not
// HTTP's optional whitespace, so a token with one around it does not read.
const nbsp = "\xc2\xa0"

// ruleCase returns the rules' case called name in kind, bound to t.
func ruleCase(t testing.TB, kind, name string) vectors.Node {
	t.Helper()
	var found vectors.Node
	ok := false
	vectors.Rules(t).Get(kind).Each(func(n string, c vectors.Node) {
		if n == name {
			found, ok = c, true
		}
	})
	if !ok {
		t.Fatalf("the rules have no %s case %q", kind, name)
	}
	return found.With(t)
}

// verifiedCase is a request that verifies at payment, enforced, at a service acting on influence, every block
// naming influence with nothing; influenceCase is one whose orders block names influence with two entries.
func verifiedCase(t testing.TB) vectors.Node { return ruleCase(t, "requests", "verified") }
func influenceCase(t testing.TB) vectors.Node {
	return ruleCase(t, "trustedRecord", "verified, private and public with owners")
}

// header returns header name of case c's request, as sent.
func header(c vectors.Node, name string) string {
	return c.Get("request").Get("headers").Get(name).Str()
}

// accept runs a fresh receiver for case c, its own nonce cache, on req under mode, failing t on an error.
func accept(
	t *testing.T, c vectors.Node, req paztporthttp.InboundRequest, mode paztporthttp.Mode,
) paztporthttp.Accepted {
	t.Helper()
	a := caseReceiver(t, c).Accept(t.Context(), req, nil, mode)
	return a
}

// withHeaders returns case c's request with its X-Path-* headers as values gives them: name to every
// value sent, in order. A header values does not name is left out.
func withHeaders(t testing.TB, c vectors.Node, values map[string][]string) paztporthttp.InboundRequest {
	t.Helper()
	base := caseRequest(t, c.Get("request"))
	return paztporthttp.NewInboundRequest(base.Method, base.Target, base.Body, func(name string) []string {
		return values[name]
	})
}

// wantServed fails t unless a is served, verified as wantVerified says.
func wantServed(t *testing.T, a paztporthttp.Accepted, wantVerified bool) {
	t.Helper()
	if a.Refusal != nil {
		t.Fatalf("refused %d %s, want served", a.Refusal.Status, a.Refusal.Body)
	}
	if a.Verified != wantVerified {
		t.Fatalf("Verified = %v, want %v", a.Verified, wantVerified)
	}
}

// wantRefused fails t unless a is refused with status and code, carrying and handing on nothing.
func wantRefused(t *testing.T, a paztporthttp.Accepted, status int, code reason.Code) {
	t.Helper()
	if a.Refusal == nil {
		t.Fatalf("served (Verified %v), want %d %s", a.Verified, status, code)
	}
	want := `{"reason":"` + string(code) + `"}`
	if a.Refusal.Status != status || string(a.Refusal.Body) != want {
		t.Fatalf("refused %d %s, want %d %s", a.Refusal.Status, a.Refusal.Body, status, want)
	}
	if a.Verified || a.Attests() || a.Inbound.Chain != nil || a.Inbound.Blocks != nil || a.HandOver != nil {
		t.Fatalf("a refusal carries Verified %v, Attests %v, Inbound %+v, HandOver %v",
			a.Verified, a.Attests(), a.Inbound, a.HandOver)
	}
}

// wantNothingCarried fails t unless a carries no chain or blocks and hands nothing on.
func wantNothingCarried(t *testing.T, a paztporthttp.Accepted) {
	t.Helper()
	if a.Verified || a.Attests() || a.Inbound.Chain != nil || a.Inbound.Blocks != nil || a.HandOver != nil {
		t.Fatalf("Verified %v, Attests %v, Inbound %+v, HandOver %v; want nothing carried",
			a.Verified, a.Attests(), a.Inbound, a.HandOver)
	}
}

// TestAcceptChainHeaderValues reads the chain header as the spec reads a header: blank is absent, only
// SP and HTAB around the token are trimmed, and of two values the first counts.
func TestAcceptChainHeaderValues(t *testing.T) {
	c := verifiedCase(t)
	tok, proof, blocks := header(c, wire.Chain), header(c, wire.Proof), header(c, wire.Extensions)
	tests := []struct {
		name   string
		values []string
		ok     bool
	}{
		{"as sent", []string{tok}, true},
		{"absent", nil, false},
		{"blank", []string{""}, false},
		{"whitespace only", []string{" \t "}, false},
		{"a trailing SP", []string{tok + " "}, true},
		{"a trailing HTAB", []string{tok + "\t"}, true},
		{"a leading SP and HTAB", []string{" \t" + tok}, true},
		{"a trailing U+00A0", []string{tok + nbsp}, false},
		{"a leading U+00A0", []string{nbsp + tok}, false},
		{"a trailing CRLF", []string{tok + "\r\n"}, false},
		{"two values, the first the chain", []string{tok, "not*base64url"}, true},
		{"two values, the second the chain", []string{"not*base64url", tok}, false},
		{"two values, the first blank", []string{"", tok}, false},
		{"two values joined", []string{tok + ", " + tok}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := withHeaders(t, c, map[string][]string{wire.Chain: tt.values, wire.Proof: {proof},
				wire.Extensions: {blocks}})
			a := accept(t, c, req, paztporthttp.ModeEnforce)
			if tt.ok {
				wantServed(t, a, true)
				if !a.Attests() {
					t.Fatal("a verified chain is not attested")
				}
				return
			}
			wantRefused(t, a, 403, reason.ChainMissing)
		})
	}
}

// TestAcceptProofHeaderValues reads the proof header the same way: a value that does not read is no
// proof, so the route is not allowed.
func TestAcceptProofHeaderValues(t *testing.T) {
	c := verifiedCase(t)
	chain, proof, blocks := header(c, wire.Chain), header(c, wire.Proof), header(c, wire.Extensions)
	tests := []struct {
		name   string
		values []string
		ok     bool
	}{
		{"as sent", []string{proof}, true},
		{"whitespace only", []string{"\t \t"}, false},
		{"a trailing SP and HTAB", []string{proof + " \t"}, true},
		{"a trailing U+00A0", []string{proof + nbsp}, false},
		{"two values, the first the proof", []string{proof, "ew"}, true},
		{"two values, the second the proof", []string{"ew", proof}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := withHeaders(t, c, map[string][]string{wire.Chain: {chain}, wire.Proof: tt.values,
				wire.Extensions: {blocks}})
			a := accept(t, c, req, paztporthttp.ModeEnforce)
			if tt.ok {
				wantServed(t, a, true)
				return
			}
			wantRefused(t, a, 403, reason.PathNotAllowed)
		})
	}
}

// TestAcceptExtensionsHeaderValues reads the blocks header the same way. In audit mode a request whose blocks
// header does not read, or that has none where its stamps commit to blocks, is refused 400 EXTENSION_MISMATCH,
// since check 9a fails, and a blank header is none.
func TestAcceptExtensionsHeaderValues(t *testing.T) {
	c := influenceCase(t)
	chain, proof, blocks := header(c, wire.Chain), header(c, wire.Proof), header(c, wire.Extensions)
	tests := []struct {
		name     string
		values   []string
		verified bool
	}{
		{"as sent", []string{blocks}, true},
		{"absent", nil, false},
		{"blank", []string{""}, false},
		{"whitespace only", []string{" "}, false},
		{"a leading HTAB and a trailing SP", []string{"\t" + blocks + " "}, true},
		{"a trailing U+00A0", []string{blocks + nbsp}, false},
		{"two values, the first the blocks", []string{blocks, "not*base64url"}, true},
		{"two values, the second the blocks", []string{"not*base64url", blocks}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string][]string{wire.Chain: {chain}, wire.Proof: {proof}, wire.Extensions: tt.values}
			a := accept(t, c, withHeaders(t, c, values), paztporthttp.ModeAudit)
			if !tt.verified {
				wantRefused(t, a, 400, reason.ExtensionMismatch)
				if a.Result == nil || a.Result.Reason != reason.ExtensionMismatch {
					t.Fatalf("Result %+v, want EXTENSION_MISMATCH", a.Result)
				}
				return
			}
			wantServed(t, a, true)
			handover.Match(t, "handed on", a.HandOver, handover.Expected(t, c.Get("expected").Get("handedOn").Raw()))
		})
	}
}

// TestNewInboundRequest takes each X-Path-* header's first value from the lookup, and "" when it gives
// none; net/http's Header.Values is such a lookup, matching names in any case.
func TestNewInboundRequest(t *testing.T) {
	h := http.Header{}
	h.Add("x-path-chain", "chain-1")
	h.Add("X-PATH-CHAIN", "chain-2")
	h.Add("X-Path-Proof", "proof-1")
	h.Add("x-path-extensions", "blocks-1")
	h.Add("X-Path-Session", "")
	h.Add("X-Path-Session", "sess-2")
	h.Add("X-Path-Response", "not read")
	body := []byte("body")
	got := paztporthttp.NewInboundRequest("POST", "/pay?x=%C3%A9", body, h.Values)
	if got.Method != "POST" || got.Target != "/pay?x=%C3%A9" || got.Chain != "chain-1" || got.Proof != "proof-1" ||
		got.Extensions != "blocks-1" || got.Session != "" || &got.Body[0] != &body[0] {
		t.Fatalf("NewInboundRequest = %+v", got)
	}

	var asked []string
	paztporthttp.NewInboundRequest("GET", "/", nil, func(name string) []string {
		asked = append(asked, name)
		return nil
	})
	slices.Sort(asked)
	if wantAsked := []string{wire.Chain, wire.Extensions, wire.Proof, wire.Session}; !slices.Equal(asked, wantAsked) {
		t.Fatalf("looked up %q, want %q", asked, wantAsked)
	}

	if got := paztporthttp.NewInboundRequest("GET", "/", nil, nil); got.Chain != "" || got.Proof != "" ||
		got.Extensions != "" || got.Session != "" {
		t.Fatalf("a nil lookup gave headers: %+v", got)
	}
}

// TestParseMode fails closed: only enforce, audit and off are modes, in any case and with whitespace
// around them, and anything else is enforce.
func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want paztporthttp.Mode
	}{
		{"enforce", paztporthttp.ModeEnforce},
		{"audit", paztporthttp.ModeAudit},
		{"off", paztporthttp.ModeOff},
		{"AUDIT", paztporthttp.ModeAudit},
		{"Off", paztporthttp.ModeOff},
		{" audit\t", paztporthttp.ModeAudit},
		{"audit\n", paztporthttp.ModeAudit},
		{"", paztporthttp.ModeEnforce},
		{"  ", paztporthttp.ModeEnforce},
		{"none", paztporthttp.ModeEnforce},
		{"audits", paztporthttp.ModeEnforce},
		{"au dit", paztporthttp.ModeEnforce},
		{"audit" + nbsp, paztporthttp.ModeEnforce},
		{"of" + "\xff", paztporthttp.ModeEnforce},
	}
	for _, tt := range tests {
		if got := paztporthttp.ParseMode(tt.in); got != tt.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
	var unset paztporthttp.Mode
	if unset != paztporthttp.ModeEnforce {
		t.Errorf("the zero Mode is %v, want enforce", unset)
	}
	for _, s := range []string{"enforce", "audit", "off"} {
		if got := paztporthttp.ParseMode(s).String(); got != s {
			t.Errorf("ParseMode(%q).String() = %q", s, got)
		}
	}
	if got := paztporthttp.ModeNone.String(); got != "none" {
		t.Errorf("ModeNone.String() = %q", got)
	}
	if got := paztporthttp.Mode(42).String(); got != "Mode(42)" {
		t.Errorf("Mode(42).String() = %q", got)
	}
}

// TestAcceptModeNotAMode enforces under a value that is no mode, as under an unset one.
func TestAcceptModeNotAMode(t *testing.T) {
	c := ruleCase(t, "attestation", "enforce, refused")
	for _, mode := range []paztporthttp.Mode{paztporthttp.Mode(42), paztporthttp.Mode(-1)} {
		a := accept(t, c, caseRequest(t, c.Get("request")), mode)
		wantRefused(t, a, 403, reason.BadSignature)
		if a.Audit {
			t.Fatalf("%v reported audit", mode)
		}
	}
}

// TestAnswers writes each answer's body exactly.
func TestAnswers(t *testing.T) {
	tests := []struct {
		name   string
		got    paztporthttp.Answer
		status int
		body   string
	}{
		{"replay", paztporthttp.Refusal(403, reason.Replay), 403, `{"reason":"REPLAY"}`},
		{"unreadable influence", paztporthttp.Refusal(400, reason.InfluenceMismatch), 400,
			`{"reason":"INFLUENCE_MISMATCH"}`},
		{"unsafe session", paztporthttp.UnsafeRefusal(), 403, `{"reason":"UNSAFE_SESSION"}`},
	}
	for _, tt := range tests {
		if tt.got.Status != tt.status || string(tt.got.Body) != tt.body {
			t.Errorf("%s: %d %s, want %d %s", tt.name, tt.got.Status, tt.got.Body, tt.status, tt.body)
		}
	}
}

// TestRefusalPanicsOnAnUnwritableCode: a code is the program's constant, so one no JSON text can carry
// is a fault in the program, as Refusal documents.
func TestRefusalPanicsOnAnUnwritableCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	paztporthttp.Refusal(403, reason.Code("A\xffB"))
}

// TestAttestRoundTrip attests a verified request's answer, and the caller's check of the header, with the chain,
// blocks and proof it sent, verifies it. What the handler does to Inbound does not change what is vouched for.
func TestAttestRoundTrip(t *testing.T) {
	c := influenceCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	sent, sentBlocks := slices.Clone(a.Inbound.Chain), slices.Clone(a.Inbound.Blocks)
	a.Inbound.Chain[len(a.Inbound.Chain)-1].Svc = "elsewhere"
	a.Inbound.Chain = a.Inbound.Chain[:1]

	body := []byte(`{"paid":true}`)
	h, ok, err := a.Attest(201, body, nil)
	if err != nil || !ok || h == "" {
		t.Fatalf("Attest = %q, %v, %v", h, ok, err)
	}

	proof, err := policy.ReadProof(header(c, wire.Proof))
	if err != nil {
		t.Fatalf("ReadProof: %v", err)
	}
	now := c.Get("now").Int()
	caller := pinnedVerifier(t, "shop", verify.Config{
		AllowedOrigins: []string{"gateway"},
		Nonces:         verify.NewMemoryNonceCache(verify.NonceTTLMs),
		Now:            func() int64 { return now },
		CallMaxAgeMs:   verify.CallMaxAgeMs,
		RunMaxAgeMs:    verify.RunMaxAgeMs,
	})
	check, err := wire.CheckResponse(t.Context(), caller, sent, sentBlocks, &proof, h, 201, body, "orders", "")
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	if !check.Result.OK() || check.Result.SuspectSvc != "payment" || check.Result.SuspectInst != "pay-1" {
		t.Fatalf("the caller's check = %+v, want OK from payment@pay-1", check.Result)
	}
	for _, other := range []struct {
		status int
		body   string
	}{{200, `{"paid":true}`}, {201, `{"paid":false}`}} {
		check, err := wire.CheckResponse(t.Context(), caller, sent, sentBlocks, &proof, h, other.status,
			[]byte(other.body), "orders", "")
		if err != nil || check.Result.Reason != reason.BindingMismatch {
			t.Fatalf("another answer (%d %s) checks as %+v, %v", other.status, other.body, check.Result, err)
		}
	}
}

// TestAttestUnattested gives no header for an answer that is not attested, that holds a label no block can carry,
// or whose binding cannot carry the request's rid, and an error only for a stamper that cannot sign.
func TestAttestUnattested(t *testing.T) {
	t.Run("not attesting", func(t *testing.T) {
		c := verifiedCase(t)
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeOff)
		wantServed(t, a, false)
		if h, ok, err := a.Attest(200, nil, nil); h != "" || ok || err != nil {
			t.Fatalf("Attest = %q, %v, %v; want unattested", h, ok, err)
		}
		if h, ok, err := (paztporthttp.Accepted{Verified: true}).Attest(200, nil, nil); h != "" || ok || err != nil {
			t.Fatalf("a hand-made Accepted attested: %q, %v, %v", h, ok, err)
		}
	})
	t.Run("a label no block can carry", func(t *testing.T) {
		c := verifiedCase(t)
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
		wantServed(t, a, true)
		for _, l := range []influence.Label{{Class: "secret", CID: "c"}, {Class: influence.Public, CID: "c\xff"}} {
			if h, ok, err := a.Attest(200, nil, []influence.Label{l}); h != "" || ok || err != nil {
				t.Fatalf("Attest(%+v) = %q, %v, %v; want unattested", l, h, ok, err)
			}
		}
	})
	t.Run("a rid the binding cannot carry", func(t *testing.T) {
		c := verifiedCase(t)
		req := minted(t, c, "rid\nrules", empties(2), nil, false)
		a := accept(t, c, req, paztporthttp.ModeEnforce)
		wantServed(t, a, true)
		if !a.Attests() {
			t.Fatal("a verified chain is not attested")
		}
		if h, ok, err := a.Attest(200, nil, nil); h != "" || ok || err != nil {
			t.Fatalf("Attest = %q, %v, %v; want unattested", h, ok, err)
		}
	})
	t.Run("no stamper", func(t *testing.T) {
		c := verifiedCase(t)
		r := caseReceiver(t, c)
		r.Stamper = nil
		a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
		wantServed(t, a, true)
		if a.Attests() {
			t.Fatal("a service with no stamp key attests")
		}
		if h, ok, err := a.Attest(200, nil, nil); h != "" || ok || err != nil {
			t.Fatalf("Attest = %q, %v, %v; want unattested", h, ok, err)
		}
	})
	t.Run("a stamper with no key", func(t *testing.T) {
		c := verifiedCase(t)
		r := caseReceiver(t, c)
		r.Stamper.Key = nil
		a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
		if h, ok, err := a.Attest(200, nil, nil); h != "" || ok || err == nil {
			t.Fatalf("Attest = %q, %v, %v; want an error", h, ok, err)
		}
	})
}

// answerLabels label a handler's answer: alice's private receipt, then public terms with no owner.
var answerLabels = []influence.Label{
	{Class: influence.Private, CID: "cid-receipt-1", Owner: "alice"},
	{Class: influence.Public, CID: "cid-terms-1"},
}

// sentTo returns the call that brought case c's request to payment, which accepted it as a: what orders sent, the
// chain and blocks payment received and the request's proof, copied before any handler touches a.
func sentTo(t *testing.T, c vectors.Node, a paztporthttp.Accepted) paztporthttp.Outbound {
	t.Helper()
	proof, err := policy.ReadProof(header(c, wire.Proof))
	if err != nil {
		t.Fatalf("ReadProof: %v", err)
	}
	return paztporthttp.Outbound{Sent: slices.Clone(a.Inbound.Chain), Blocks: slices.Clone(a.Inbound.Blocks),
		Proof: &proof}
}

// checkingCaller returns orders' caller for case c, checking the answers to its calls with a verifier pinned to
// the case's material under the settings ext, over a nonce cache of its own.
func checkingCaller(t *testing.T, c vectors.Node, ext verify.Extensions) *paztporthttp.Caller {
	t.Helper()
	now := c.Get("now").Int()
	return &paztporthttp.Caller{
		Stamper: &stamp.Stamper{Svc: "orders"},
		Verifier: pinnedVerifier(t, c.Get("material").Str(), verify.Config{
			AllowedOrigins: c.Get("allowedOrigins").Strs(),
			Nonces:         verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int()),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
			Extensions:     ext,
		}),
	}
}

// responseBlock returns the block the response header h holds, read by the SDK's own block reader.
func responseBlock(t *testing.T, h string) stamp.Block {
	t.Helper()
	v, err := json.ReadToken(h)
	if err != nil {
		t.Fatalf("the response header: %v", err)
	}
	field, ok := json.Field(v, "block")
	if !ok {
		t.Fatal("the response header holds no block")
	}
	text, err := json.Wire(field)
	if err != nil {
		t.Fatal(err)
	}
	b, err := stamp.ParseBlock(text)
	if err != nil {
		t.Fatalf("the response's block: %v", err)
	}
	return b
}

// wantReceived fails t unless r is the check of a response that gave code, added want and was refused as
// refused says.
func wantReceived(t *testing.T, r paztporthttp.Received, code reason.Code, want []influence.Entry, refused bool) {
	t.Helper()
	if r.Check == nil || r.Check.Result.Reason != code {
		t.Fatalf("Check = %+v, want %s", r.Check, code)
	}
	if !slices.Equal(r.Entries, want) || r.Refused != refused {
		t.Fatalf("Entries %+v, Refused %v; want %+v, %v", r.Entries, r.Refused, want, refused)
	}
}

// untrustedFrom is the one entry an answer nobody vouched for adds from payment, by its result hash.
func untrustedFrom(status int, body []byte) []influence.Entry {
	return []influence.Entry{{Class: influence.LocalUntrusted, Src: "http:payment", H: wire.ResultHash(status, body)}}
}

// TestAnActingResponderSignsItsLabels: at a responder acting on influence, the answer's block names influence with
// each label, in order, and requires influence, so the caller acting on influence that checks it adds one entry per
// label, from the service it called, by the answer's result hash.
func TestAnActingResponderSignsItsLabels(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	o := sentTo(t, c, a)
	body := []byte(`{"receipt":"r-1"}`)
	h, ok, err := a.Attest(201, body, answerLabels)
	if err != nil || !ok || h == "" {
		t.Fatalf("Attest = %q, %v, %v", h, ok, err)
	}
	want, err := influence.ResponseBlock(answerLabels, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := responseBlock(t, h); !bytes.Equal(got.Wire(), want.Wire()) ||
		!slices.Equal(got.Requires(), []string{influence.Name}) {
		t.Fatalf("the response's block is %s, want %s, requiring influence", got.Wire(), want.Wire())
	}
	got, err := checkingCaller(t, c, actsOnInfluence(t)).Check(t.Context(), o, h, 201, body)
	if err != nil {
		t.Fatal(err)
	}
	hash := wire.ResultHash(201, body)
	wantReceived(t, got, reason.OK, []influence.Entry{answerLabels[0].Entry("http:payment", hash),
		answerLabels[1].Entry("http:payment", hash)}, false)
}

// TestAnActingResponderWithNoLabelNamesInfluenceWithNothing: a responder acting on influence names it on every
// answer it attests, [] for one with no label, requiring nothing; such an answer adds no entry.
func TestAnActingResponderWithNoLabelNamesInfluenceWithNothing(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	o := sentTo(t, c, a)
	body := []byte(`{"paid":true}`)
	h, ok, err := a.Attest(200, body, nil)
	if err != nil || !ok {
		t.Fatalf("Attest = %q, %v, %v", h, ok, err)
	}
	if got := string(responseBlock(t, h).Wire()); got != `{"items":{"influence":[]},"requires":[]}` {
		t.Fatalf("the response's block is %s, want influence named with nothing", got)
	}
	got, err := checkingCaller(t, c, actsOnInfluence(t)).Check(t.Context(), o, h, 200, body)
	if err != nil {
		t.Fatal(err)
	}
	wantReceived(t, got, reason.OK, nil, false)
}

// TestALabelledAnswerAtAResponderNotActingOnInfluenceIsUnattested: a responder that does not act on influence,
// acting on nothing or on another extension, cannot carry a label, so a labelled answer goes unattested, with no
// error, and its caller adds one local-untrusted entry for it, stricter than any label; an answer with no label is
// attested with the empty block.
func TestALabelledAnswerAtAResponderNotActingOnInfluenceIsUnattested(t *testing.T) {
	c := verifiedCase(t)
	other, err := verify.NewExtensions([]string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, ext := range map[string]verify.Extensions{"acting on nothing": {}, "acting on another": other} {
		t.Run(name, func(t *testing.T) {
			r := caseReceiver(t, c)
			r.Extensions, r.Verifier = ext, caseVerifierWith(t, c, ext)
			a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
			wantServed(t, a, true)
			o := sentTo(t, c, a)
			body := []byte(`{"receipt":"r-1"}`)
			if h, ok, err := a.Attest(200, body, answerLabels[:1]); h != "" || ok || err != nil {
				t.Fatalf("Attest = %q, %v, %v; want unattested", h, ok, err)
			}
			got, err := checkingCaller(t, c, actsOnInfluence(t)).Check(t.Context(), o, "", 200, body)
			if err != nil {
				t.Fatal(err)
			}
			wantReceived(t, got, reason.ChainMissing, untrustedFrom(200, body), false)

			h, ok, err := a.Attest(200, body, nil)
			if err != nil || !ok {
				t.Fatalf("Attest with no label = %q, %v, %v", h, ok, err)
			}
			if got := responseBlock(t, h); got.Commit() != stamp.EmptyBlock.Commit() {
				t.Fatalf("the response's block is %s, want the empty block", got.Wire())
			}
		})
	}
}

// TestAResponseBlockPastTheWireLimitIsUnattestedWithNoError: labels whose response header would pass the wire limit
// leave the answer unattested, nothing dropped to make room, and that is no error: the caller adds one
// local-untrusted entry. The block alone is within the limit; with the stamp beside it the header is not.
func TestAResponseBlockPastTheWireLimitIsUnattestedWithNoError(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	big := []influence.Label{{Class: influence.Public, CID: strings.Repeat("c", json.WireBytes-200)}}
	if b, err := influence.ResponseBlock(big, nil); err != nil || len(b.Wire()) > json.WireBytes {
		t.Fatalf("the block alone does not fit: %d bytes, %v", len(b.Wire()), err)
	}
	if h, ok, err := a.Attest(200, nil, big); h != "" || ok || err != nil {
		t.Fatalf("Attest = %d characters, %v, %v; want unattested", len(h), ok, err)
	}
	if h, ok, err := a.Attest(200, nil, answerLabels); h == "" || !ok || err != nil {
		t.Fatalf("Attest of labels that fit = %q, %v, %v", h, ok, err)
	}
}

// TestAResponseRefusedAtNineCIsRefused: a labelled answer requires influence, so a caller that does not act on it
// refuses the answer at check 9c and fails the call; the answer still adds its one local-untrusted entry. A response
// that fails any other check is not refused, only untrusted.
func TestAResponseRefusedAtNineCIsRefused(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	o := sentTo(t, c, a)
	body := []byte(`{"receipt":"r-1"}`)
	h, ok, err := a.Attest(201, body, answerLabels)
	if err != nil || !ok {
		t.Fatalf("Attest = %q, %v, %v", h, ok, err)
	}
	got, err := checkingCaller(t, c, verify.Extensions{}).Check(t.Context(), o, h, 201, body)
	if err != nil {
		t.Fatal(err)
	}
	wantReceived(t, got, reason.ExtensionRequired, untrustedFrom(201, body), true)

	other := []byte(`{"receipt":"r-2"}`)
	got, err = checkingCaller(t, c, actsOnInfluence(t)).Check(t.Context(), o, h, 201, other)
	if err != nil {
		t.Fatal(err)
	}
	wantReceived(t, got, reason.BindingMismatch, untrustedFrom(201, other), false)
}

// TestALabelBesideAnEntryIsOneUntrustedEntry: a response that verifies, whose block names influence with a label
// and an item that is not one, an entry, adds no label: one local-untrusted entry, and it is not refused.
func TestALabelBesideAnEntryIsOneUntrustedEntry(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	o := sentTo(t, c, a)
	body := []byte(`{"receipt":"r-1"}`)
	hash := wire.ResultHash(200, body)
	block, err := stamp.NewBlock(map[string][]string{influence.Name: {
		`{"cid":"cid-receipt-1","cls":"private","owner":"alice"}`,
		`{"cls":"third-party","h":"h2","src":"web:example.com"}`,
	}}, []string{influence.Name})
	if err != nil {
		t.Fatal(err)
	}
	s, err := caseReceiver(t, c).Stamper.Respond(o.Sent, hash, o.Sent[0].RID, block)
	if err != nil {
		t.Fatal(err)
	}
	h, err := wire.EncodeResponse(s, block)
	if err != nil {
		t.Fatal(err)
	}
	got, err := checkingCaller(t, c, actsOnInfluence(t)).Check(t.Context(), o, h, 200, body)
	if err != nil {
		t.Fatal(err)
	}
	wantReceived(t, got, reason.OK, untrustedFrom(200, body), false)
	if items := got.Check.Response(influence.Name); items == nil || len(items.Items) != 2 {
		t.Fatalf("the check hands over %+v, want both items", items)
	}
}

// mintedChain returns the token of a chain gateway then orders sign for req at payment, at case c's now, in the
// request rid, their stamps committing to signed[0] and signed[1]. orders' stamp is signed with payment's key
// where forged, so that the live order gives BAD_SIGNATURE.
func mintedChain(
	t *testing.T, c vectors.Node, rid string, req paztporthttp.InboundRequest, signed stamp.Blocks, forged bool,
) string {
	t.Helper()
	now := c.Get("now").Int()
	gwKey, _ := vectors.RulesKey(t, "gateway")
	ordKey, _ := vectors.RulesKey(t, "orders")
	if forged {
		ordKey, _ = vectors.RulesKey(t, "payment")
	}
	gw := &stamp.Stamper{Svc: "gateway", Inst: "gw-1", Key: gwKey, Origin: true,
		NewRID: func() string { return rid }, Now: func() int64 { return now - 1500 }}
	ord := &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: ordKey, Now: func() int64 { return now - 500 }}
	first, _, err := gw.Next(nil, "orders", "bind-gateway-to-orders", signed[0], policy.ProofBundle{})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	bind, err := wire.Bind(req.Method, req.Target, req.Body)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	chain, _, err := ord.Next(first, "payment", bind, signed[1], policy.ProofBundle{})
	if err != nil {
		t.Fatalf("orders: %v", err)
	}
	tok, err := wire.EncodeChain(chain)
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	return tok
}

// minted returns case c's request with mintedChain's chain in rid, committing to signed and forged as it says,
// and the blocks header holding sent, or none where sent is nil.
func minted(
	t *testing.T, c vectors.Node, rid string, signed, sent stamp.Blocks, forged bool,
) paztporthttp.InboundRequest {
	t.Helper()
	req := caseRequest(t, c.Get("request"))
	req.Chain = mintedChain(t, c, rid, req, signed, forged)
	req.Extensions = ""
	if sent != nil {
		req.Extensions = blocksHeader(t, sent)
	}
	return req
}

// blocksHeader returns the X-Path-Extensions value holding bs.
func blocksHeader(t *testing.T, bs stamp.Blocks) string {
	t.Helper()
	tok, err := wire.EncodeBlocks(bs)
	if err != nil {
		t.Fatalf("EncodeBlocks: %v", err)
	}
	return tok
}

// empties returns n empty blocks.
func empties(n int) stamp.Blocks { return make(stamp.Blocks, n) }

// itemsBlock returns a block naming influence with items, each the canonical text of one value.
func itemsBlock(t *testing.T, items ...string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{influence.Name: items}, nil)
	if err != nil {
		t.Fatalf("NewBlock: %v", err)
	}
	return b
}

// entryItem is one influence entry, as an item's canonical text.
const entryItem = `{"cls":"public","h":"h-1","src":"http:catalogue"}`

// TestAcceptTargets binds the target exactly as received: a bare trailing "?" ends an empty query, and
// a target that is not valid UTF-8 has no binding, so no chain matches it.
func TestAcceptTargets(t *testing.T) {
	c := verifiedCase(t)
	for _, tt := range []struct {
		target string
		ok     bool
	}{{"/pay", true}, {"/pay?", true}, {"/pay?x", false}, {"/pay%3F", false}, {"/pay\xff", false}, {"", false}} {
		req := caseRequest(t, c.Get("request"))
		req.Target = tt.target
		a := accept(t, c, req, paztporthttp.ModeEnforce)
		if tt.ok {
			wantServed(t, a, true)
			continue
		}
		wantRefused(t, a, 403, reason.BindingMismatch)
	}
}

// TestAcceptResults reports the live order's result whenever it ran, and audit mode with it, and never
// in the refusal.
func TestAcceptResults(t *testing.T) {
	t.Run("a peer that is not the last signer", func(t *testing.T) {
		c := ruleCase(t, "refusals", "a peer that is not the last signer is named, but not to the caller")
		a := caseReceiver(t, c).Accept(t.Context(), caseRequest(t, c.Get("request")), casePeer(c.Get("peer")),
			paztporthttp.ModeEnforce)
		wantRefused(t, a, 403, reason.PeerMismatch)
		want := verify.Result{Reason: reason.PeerMismatch, SuspectSvc: "gateway", SuspectInst: "10.1.0.9"}
		if a.Result == nil || *a.Result != want || a.Audit {
			t.Fatalf("Result %+v, Audit %v; want %+v, not audit", a.Result, a.Audit, want)
		}
	})
	t.Run("audit, failed", func(t *testing.T) {
		c := ruleCase(t, "trustedRecord", "a chain that failed in audit mode")
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeAudit)
		wantServed(t, a, false)
		if a.Result == nil || a.Result.Reason != reason.BadSignature || !a.Audit || a.Inbound.Chain == nil {
			t.Fatalf("Result %+v, Audit %v, Inbound %+v", a.Result, a.Audit, a.Inbound)
		}
	})
	t.Run("audit, an item that does not read", func(t *testing.T) {
		c := ruleCase(t, "influenceItems", "audit, on a chain that verifies otherwise")
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeAudit)
		wantRefused(t, a, 400, reason.InfluenceMismatch)
		if a.Result == nil || !a.Result.OK() || !a.Audit {
			t.Fatalf("Result %+v, Audit %v; want the verdict OK, in audit", a.Result, a.Audit)
		}
	})
	t.Run("off", func(t *testing.T) {
		c := verifiedCase(t)
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeOff)
		wantServed(t, a, false)
		if a.Result != nil || a.Audit || a.Inbound.Chain == nil {
			t.Fatalf("Result %+v, Audit %v, Inbound %+v; want the chain carried and nothing verified",
				a.Result, a.Audit, a.Inbound)
		}
	})
}

// TestAcceptNoModeVerifiesOnce verifies a request at most once, since the live order spends its nonce
// key: with no mode, the chain is verified to attest, so the same request again is a replay that is
// served, unverified and unattested.
func TestAcceptNoModeVerifiesOnce(t *testing.T) {
	c := verifiedCase(t)
	r := caseReceiver(t, c)
	req := caseRequest(t, c.Get("request"))
	for i, want := range []reason.Code{reason.OK, reason.Replay} {
		a := r.Accept(t.Context(), req, nil, paztporthttp.ModeNone)
		wantServed(t, a, want == reason.OK)
		if a.Attests() != (want == reason.OK) || a.Result == nil || a.Result.Reason != want || a.Audit {
			t.Fatalf("entry %d: Attests %v, Result %+v, Audit %v; want %s", i, a.Attests(), a.Result, a.Audit, want)
		}
	}

	// With no chain there is nothing to attest, so nothing is verified.
	req.Chain = ""
	a := caseReceiver(t, c).Accept(t.Context(), req, nil, paztporthttp.ModeNone)
	wantServed(t, a, false)
	if a.Result != nil {
		t.Fatalf("a request with no chain was verified: %+v", a.Result)
	}
}

// countingCache is a nonce cache that counts the keys offered to it.
type countingCache struct {
	*verify.MemoryNonceCache
	calls int
}

func (c *countingCache) SeenBefore(ctx context.Context, key string, now int64) (bool, error) {
	c.calls++
	return c.MemoryNonceCache.SeenBefore(ctx, key, now)
}

// TestAcceptLiveOrderOnce runs the live order at most once per request, in every mode and wherever it
// stops, since it spends the request's nonce key: a second run would report REPLAY for the first run's
// result.
func TestAcceptLiveOrderOnce(t *testing.T) {
	verified, refused := verifiedCase(t), ruleCase(t, "attestation", "enforce, refused")
	noProof := func(t *testing.T) paztporthttp.InboundRequest {
		req := caseRequest(t, verified.Get("request"))
		req.Proof = ""
		return req
	}
	for _, tt := range []struct {
		name  string
		c     vectors.Node
		req   func(*testing.T) paztporthttp.InboundRequest
		calls int // the keys the cache is offered: one once checks 1 to 9 hold, else none
	}{
		{"verified", verified, func(t *testing.T) paztporthttp.InboundRequest {
			return caseRequest(t, verified.Get("request"))
		}, 1},
		{"no proof", verified, noProof, 1},
		{"forged", refused, func(t *testing.T) paztporthttp.InboundRequest {
			return caseRequest(t, refused.Get("request"))
		}, 0},
	} {
		for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit, paztporthttp.ModeNone} {
			t.Run(tt.name+", "+mode.String(), func(t *testing.T) {
				r := caseReceiver(t, tt.c)
				now := tt.c.Get("now").Int()
				cache := &countingCache{MemoryNonceCache: verify.NewMemoryNonceCache(verify.NonceTTLMs)}
				r.Verifier = pinnedVerifier(t, "shop", verify.Config{
					AllowedOrigins: []string{"gateway"},
					Nonces:         cache,
					Now:            func() int64 { return now },
					CallMaxAgeMs:   verify.CallMaxAgeMs,
					RunMaxAgeMs:    verify.RunMaxAgeMs,
					Extensions:     caseSettings(t, tt.c),
				})
				r.Accept(t.Context(), tt.req(t), nil, mode)
				if cache.calls != tt.calls {
					t.Fatalf("the cache was offered %d keys, want %d", cache.calls, tt.calls)
				}
			})
		}
	}

	t.Run("audit reports the first run's result", func(t *testing.T) {
		a := accept(t, verified, noProof(t), paztporthttp.ModeAudit)
		wantServed(t, a, false)
		if a.Result == nil || a.Result.Reason != reason.PathNotAllowed || !a.Audit || a.Attests() {
			t.Fatalf("Result %+v, Audit %v, Attests %v; want PATH_NOT_ALLOWED in audit, unattested",
				a.Result, a.Audit, a.Attests())
		}
	})
}

// failingCache is a nonce cache that cannot answer.
type failingCache struct{ err error }

func (f failingCache) SeenBefore(context.Context, string, int64) (bool, error) { return false, f.err }
func (failingCache) TTL() int64                                                { return verify.NonceTTLMs }

// failingReceiver is case c's receiver, its verifier's nonce cache one that fails with err.
func failingReceiver(t *testing.T, c vectors.Node, err error) *paztporthttp.Receiver {
	t.Helper()
	r := caseReceiver(t, c)
	now := c.Get("now").Int()
	r.Verifier = pinnedVerifier(t, c.Get("material").Str(), verify.Config{
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Nonces:         failingCache{err},
		Now:            func() int64 { return now },
		CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
		RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
		Extensions:     caseSettings(t, c),
	})
	return r
}

// TestAcceptCacheError decides a request whose nonce cache cannot answer: enforce refuses it 503 with no body,
// and audit and no mode serve it unverified and unattested, carrying its chain and blocks once check 9a has held
// on them and handing the items on as not verified, as a request that fails in audit mode is. Either way the
// cache's error is exposed, and nothing is verified, attested or delivered. An origin carries nothing in any
// mode. ctx reaches the cache.
func TestAcceptCacheError(t *testing.T) {
	c := influenceCase(t)
	down := errors.New("the store is down")
	received := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeOff)
	if received.Inbound.Chain == nil || len(received.Inbound.Blocks) != len(received.Inbound.Chain) {
		t.Fatalf("the case carries Inbound %+v; want its chain and blocks", received.Inbound)
	}
	wantUndecided := func(t *testing.T, a paztporthttp.Accepted, refused bool) {
		t.Helper()
		if !errors.Is(a.CacheErr, down) {
			t.Fatalf("CacheErr = %v, want the cache's", a.CacheErr)
		}
		if refused {
			if a.Refusal == nil || a.Refusal.Status != 503 || len(a.Refusal.Body) != 0 {
				t.Fatalf("Refusal = %+v, want 503 and no body", a.Refusal)
			}
		} else if a.Refusal != nil {
			t.Fatalf("Refusal = %+v, want the request served", a.Refusal)
		}
		if _, ok := a.Delivery(); ok || a.Verified || a.Attests() || a.Result != nil || a.Audit {
			t.Fatalf("Accepted = %+v with the error, want nothing verified", a)
		}
	}
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit, paztporthttp.ModeNone} {
		t.Run(mode.String(), func(t *testing.T) {
			a := failingReceiver(t, c, down).Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
			wantUndecided(t, a, mode == paztporthttp.ModeEnforce)
			if mode == paztporthttp.ModeEnforce {
				if a.Inbound.Chain != nil || a.Inbound.Blocks != nil || a.HandOver != nil {
					t.Fatalf("a refusal carries Inbound %+v, HandOver %v", a.Inbound, a.HandOver)
				}
				return
			}
			if !reflect.DeepEqual(a.Inbound, received.Inbound) {
				t.Fatalf("Inbound %+v; want the chain and blocks as received", a.Inbound)
			}
			if a.HandOver == nil || a.HandOver.Verified() {
				t.Fatalf("HandOver %v; want the items handed on, not verified", a.HandOver)
			}
			handover.Match(t, "handed on", a.HandOver, handover.Expected(t, c.Get("expected").Get("handedOn").Raw()))
		})
	}
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit} {
		t.Run("origin, "+mode.String(), func(t *testing.T) {
			r := failingReceiver(t, c, down)
			r.Origin, r.Stamper.Origin = true, true
			a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
			wantUndecided(t, a, mode == paztporthttp.ModeEnforce)
			if a.Inbound.Chain != nil || a.Inbound.Blocks != nil || a.HandOver != nil {
				t.Fatalf("an origin carries Inbound %+v, HandOver %v", a.Inbound, a.HandOver)
			}
		})
	}

	r := caseReceiver(t, c)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r.Verifier = pinnedVerifier(t, "shop", verify.Config{
		AllowedOrigins: []string{"gateway"},
		Nonces:         ctxCache{},
		Now:            func() int64 { return c.Get("now").Int() },
		CallMaxAgeMs:   verify.CallMaxAgeMs,
		RunMaxAgeMs:    verify.RunMaxAgeMs,
		Extensions:     caseSettings(t, c),
	})
	a := r.Accept(ctx, caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
	if !errors.Is(a.CacheErr, context.Canceled) {
		t.Fatalf("CacheErr = %v, want the cancelled context's", a.CacheErr)
	}
}

// askedCache is a nonce cache that fails with err and counts how often it is asked.
type askedCache struct {
	err   error
	asked *int
}

func (c askedCache) SeenBefore(context.Context, string, int64) (bool, error) {
	*c.asked++
	return false, c.err
}
func (askedCache) TTL() int64 { return verify.NonceTTLMs }

// TestAcceptDownCacheNeverMasksBlocksThatFail: blocks that fail check 9a fail verification before the nonce cache
// is asked, so a cache that is down never turns the request into a 503. Enforce refuses it 403
// EXTENSION_MISMATCH; audit serves past the verdict, then refuses it 400 EXTENSION_MISMATCH, the verdict in its
// Result. Either way the cache is never called. An item that does not read is the service's to refuse, after
// verification: audit, having no verdict from a cache that is down, still refuses it 400 INFLUENCE_MISMATCH.
func TestAcceptDownCacheNeverMasksBlocksThatFail(t *testing.T) {
	c := verifiedCase(t)
	req := withHeaders(t, c, map[string][]string{
		wire.Chain:      {header(c, wire.Chain)},
		wire.Proof:      {header(c, wire.Proof)},
		wire.Extensions: {"not*base64url"},
	})
	downReceiver := func(t *testing.T, c vectors.Node, asked *int) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		r.Verifier = pinnedVerifier(t, c.Get("material").Str(), verify.Config{
			AllowedOrigins: c.Get("allowedOrigins").Strs(),
			Nonces:         askedCache{errors.New("the store is down"), asked},
			Now:            func() int64 { return c.Get("now").Int() },
			CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
			Extensions:     caseSettings(t, c),
		})
		return r
	}
	for _, tt := range []struct {
		mode   paztporthttp.Mode
		status int
	}{{paztporthttp.ModeEnforce, 403}, {paztporthttp.ModeAudit, 400}} {
		t.Run(tt.mode.String(), func(t *testing.T) {
			asked := 0
			a := downReceiver(t, c, &asked).Accept(t.Context(), req, nil, tt.mode)
			wantRefused(t, a, tt.status, reason.ExtensionMismatch)
			if a.CacheErr != nil || asked != 0 {
				t.Fatalf("CacheErr = %v, cache asked %d times; want none and never", a.CacheErr, asked)
			}
			audit := tt.mode == paztporthttp.ModeAudit
			if a.Result == nil || a.Result.Reason != reason.ExtensionMismatch || a.Audit != audit {
				t.Fatalf("Result %+v, Audit %v; want the verdict EXTENSION_MISMATCH", a.Result, a.Audit)
			}
		})
	}
	t.Run("audit, an item that does not read", func(t *testing.T) {
		c := ruleCase(t, "influenceItems", "audit, on a chain that verifies otherwise")
		asked := 0
		a := downReceiver(t, c, &asked).Accept(t.Context(), caseRequest(t, c.Get("request")), nil,
			paztporthttp.ModeAudit)
		wantRefused(t, a, 400, reason.InfluenceMismatch)
		if a.CacheErr == nil || asked != 1 {
			t.Fatalf("CacheErr = %v, cache asked %d times; want the cache's error, once", a.CacheErr, asked)
		}
	})
}

// TestUnavailable is 503 and no body.
func TestUnavailable(t *testing.T) {
	if a := paztporthttp.Unavailable(); a.Status != 503 || len(a.Body) != 0 {
		t.Fatalf("Unavailable = %+v", a)
	}
}

// TestAcceptDelivery names the delivery of a request verified at this hop, from its first stamp's rid and
// its last stamp's signer, receiver and binding, and of no other.
func TestAcceptDelivery(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	d, ok := a.Delivery()
	chain := a.Inbound.Chain
	last := chain[len(chain)-1]
	want := paztporthttp.Delivery{RID: chain[0].RID, Svc: last.Svc, Rcv: last.Rcv, Bind: last.Bind}
	if !ok || d != want || d.RID == "" || d.Svc == "" || d.Rcv == "" || d.Bind == "" {
		t.Fatalf("Delivery = %+v, %v; want %+v", d, ok, want)
	}
	// With no mode, a request verified to attest is verified at this hop too.
	if d, ok := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeNone).Delivery(); !ok || d != want {
		t.Fatalf("no mode: Delivery = %+v, %v; want %+v", d, ok, want)
	}

	none := func(name string, a paztporthttp.Accepted) {
		if d, ok := a.Delivery(); ok || d != (paztporthttp.Delivery{}) {
			t.Errorf("%s: Delivery = %+v, %v; want none", name, d, ok)
		}
	}
	none("off", accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeOff))
	none("audit, failed", accept(t, ruleCase(t, "trustedRecord", "a chain that failed in audit mode"),
		caseRequest(t, ruleCase(t, "trustedRecord", "a chain that failed in audit mode").Get("request")),
		paztporthttp.ModeAudit))
	o := caseReceiver(t, c)
	o.Origin, o.Stamper.Origin = true, true
	none("origin", o.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce))
	none("the zero Accepted", paztporthttp.Accepted{})
}

// ctxCache answers with its context's error, and otherwise records nothing.
type ctxCache struct{}

func (ctxCache) SeenBefore(ctx context.Context, _ string, _ int64) (bool, error) {
	return false, ctx.Err()
}
func (ctxCache) TTL() int64 { return verify.NonceTTLMs }

// TestAcceptModeWithoutVerifier panics on a receiver, an origin included, that is to verify requests
// under a mode but holds no verifier, rather than serve them unverified; with no mode, or off, there is
// nothing to verify.
func TestAcceptModeWithoutVerifier(t *testing.T) {
	c := verifiedCase(t)
	req := caseRequest(t, c.Get("request"))
	for _, tt := range []struct {
		mode   paztporthttp.Mode
		origin bool
		panics bool
	}{
		{paztporthttp.ModeEnforce, false, true},
		{paztporthttp.ModeAudit, false, true},
		{paztporthttp.Mode(42), false, true},
		{paztporthttp.ModeNone, false, false},
		{paztporthttp.ModeOff, false, false},
		{paztporthttp.ModeEnforce, true, true},
		{paztporthttp.ModeAudit, true, true},
		{paztporthttp.ModeNone, true, false},
		{paztporthttp.ModeOff, true, false},
	} {
		func() {
			r := caseReceiver(t, c)
			r.Verifier, r.Origin, r.Stamper.Origin = nil, tt.origin, tt.origin
			defer func() {
				if got := recover() != nil; got != tt.panics {
					t.Errorf("%v, origin %v: panicked %v, want %v", tt.mode, tt.origin, got, tt.panics)
				}
			}()
			a := r.Accept(t.Context(), req, nil, tt.mode)
			if a.Verified || a.Attests() {
				t.Errorf("%v, origin %v: %+v", tt.mode, tt.origin, a)
			}
		}()
	}
}

// TestAcceptOriginMismatch panics on a receiver whose Origin and its stamper's disagree, in every mode: it
// would carry what a request brings and start new trees, or the reverse, which is a fault in the program.
// A receiver with no stamper has nothing to disagree with.
func TestAcceptOriginMismatch(t *testing.T) {
	c := verifiedCase(t)
	req := caseRequest(t, c.Get("request"))
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeNone, paztporthttp.ModeOff} {
		for _, tt := range []struct {
			origin, stamperOrigin, noStamper, panics bool
		}{
			{origin: true, stamperOrigin: false, panics: true},
			{origin: false, stamperOrigin: true, panics: true},
			{origin: true, stamperOrigin: true},
			{origin: false, stamperOrigin: false},
			{origin: true, noStamper: true},
		} {
			func() {
				r := caseReceiver(t, c)
				r.Origin, r.Stamper.Origin = tt.origin, tt.stamperOrigin
				if tt.noStamper {
					r.Stamper = nil
				}
				defer func() {
					if got := recover() != nil; got != tt.panics {
						t.Errorf("%v, %+v: panicked %v, want %v", mode, tt, got, tt.panics)
					}
				}()
				r.Accept(t.Context(), req, nil, mode)
			}()
		}
	}
}

// TestAcceptOrigin starts the request tree afresh: an origin carries neither the chain nor the blocks, an item
// that does not read included, never takes the chain as verified and never attests. Under a mode it still runs
// the live order: enforce refuses a request that fails it, and audit reports it.
func TestAcceptOrigin(t *testing.T) {
	origin := func(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		r.Origin, r.Stamper.Origin = true, true
		return r
	}

	t.Run("enforce, no chain", func(t *testing.T) {
		c := verifiedCase(t)
		req := caseRequest(t, c.Get("request"))
		req.Chain = ""
		a := origin(t, c).Accept(t.Context(), req, nil, paztporthttp.ModeEnforce)
		wantRefused(t, a, 403, reason.ChainMissing)
		if a.Result == nil || a.Result.Reason != reason.ChainMissing || a.Audit {
			t.Fatalf("Result %+v, Audit %v", a.Result, a.Audit)
		}
	})
	t.Run("audit, no chain", func(t *testing.T) {
		c := verifiedCase(t)
		req := caseRequest(t, c.Get("request"))
		req.Chain = ""
		a := origin(t, c).Accept(t.Context(), req, nil, paztporthttp.ModeAudit)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
		if a.Result == nil || a.Result.Reason != reason.ChainMissing || !a.Audit {
			t.Fatalf("Result %+v, Audit %v; want CHAIN_MISSING in audit", a.Result, a.Audit)
		}
	})
	t.Run("enforce, a chain that verifies", func(t *testing.T) {
		c := influenceCase(t)
		a := origin(t, c).Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
		if a.Result == nil || !a.Result.OK() {
			t.Fatalf("Result %+v, want OK", a.Result)
		}
	})
	t.Run("audit, an item that does not read", func(t *testing.T) {
		c := ruleCase(t, "influenceItems", "audit, on a chain that verifies otherwise")
		a := origin(t, c).Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeAudit)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
		if a.Result == nil || !a.Result.OK() || !a.Audit {
			t.Fatalf("Result %+v, Audit %v; want the verdict OK, in audit", a.Result, a.Audit)
		}
	})
	t.Run("no mode or off verifies nothing", func(t *testing.T) {
		c := ruleCase(t, "influenceItems", "an origin carries none, so has none to read")
		for _, mode := range []paztporthttp.Mode{paztporthttp.ModeNone, paztporthttp.ModeOff} {
			r := failingReceiver(t, c, errors.New("verified at an origin"))
			a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
			wantServed(t, a, false)
			wantNothingCarried(t, a)
			if a.Result != nil || a.Audit {
				t.Fatalf("%v: Result %+v, Audit %v; want nothing verified", mode, a.Result, a.Audit)
			}
		}
	})
}

// The entries the write-rule tests hand on or read: alice's private data, a third-party ticket, a local-untrusted
// search result and a public page.
const privateItem = `{"cls":"private","h":"h-card","owner":"alice","src":"http:cards"}`

var (
	thirdPartyRead = influence.Entry{
		Class: influence.ThirdParty, Src: "ticket:t-1", H: "h-ticket", CID: "cid-1", HasCID: true,
	}
	localUntrustedRead = influence.Entry{Class: influence.LocalUntrusted, Src: "http:search", H: "h-search"}
	publicRead         = influence.Entry{Class: influence.Public, Src: "http:catalogue", H: "h-page"}
)

// privateRead is a private entry whose owner is owner.
func privateRead(owner string) influence.Entry {
	return influence.Entry{Class: influence.Private, Src: "http:cards", H: "h-" + owner, Owner: owner}
}

// wantWrite fails t unless a's guarded public write to owner, having read read, is want.
func wantWrite(t *testing.T, a paztporthttp.Accepted, read []influence.Entry, owner string, want reason.Code) {
	t.Helper()
	if got := a.PublicWrite(read, owner); got != want {
		t.Errorf("PublicWrite(%v, %q) = %s, want %s", read, owner, got, want)
	}
}

// wantRecord fails t unless whether a trusted record may be written from a, having read read, is want.
func wantRecord(t *testing.T, a paztporthttp.Accepted, read []influence.Entry, want bool) {
	t.Helper()
	if got := a.TrustedRecord(read); got != want {
		t.Errorf("TrustedRecord(%v) = %v, want %v", read, got, want)
	}
}

// silentOrigin is a chain's blocks whose origin's, gateway's, does not name influence, and whose last, orders',
// names it with one public entry: every entry trusted, and one hop that may have read anything.
func silentOrigin(t *testing.T) stamp.Blocks {
	return stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, entryItem)}
}

// everyNaming is a chain's blocks whose origin's names influence with nothing and whose last names it with items.
func everyNaming(t *testing.T, items ...string) stamp.Blocks {
	return stamp.Blocks{itemsBlock(t), itemsBlock(t, items...)}
}

// TestAGuardedWriteWhoseOriginBlockDoesNotNameInfluenceIsDenied: a request whose chain verified, but whose origin
// block does not name influence, is denied a guarded public write to any owner, and no trusted record is written
// from it, though its only entry is public: that hop may have read anything. The same entries with every stamp
// naming influence are allowed both.
func TestAGuardedWriteWhoseOriginBlockDoesNotNameInfluenceIsDenied(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, minted(t, c, "rid-silent", silentOrigin(t), silentOrigin(t), false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	wantWrite(t, a, nil, "", reason.InfluenceDenied)
	wantWrite(t, a, nil, "bob", reason.InfluenceDenied)
	wantWrite(t, a, []influence.Entry{publicRead}, "bob", reason.InfluenceDenied)
	wantRecord(t, a, nil, false)

	named := everyNaming(t, entryItem)
	b := accept(t, c, minted(t, c, "rid-named", named, named, false), paztporthttp.ModeEnforce)
	wantServed(t, b, true)
	wantWrite(t, b, nil, "", reason.OK)
	wantWrite(t, b, nil, "bob", reason.OK)
	wantRecord(t, b, nil, true)
}

// TestTheSameRequestMayBeRead: the request denied a guarded write is served, verified and attested, since only a
// write is refused for a silent hop; for a read the owner-aware rule alone decides, and allows it.
func TestTheSameRequestMayBeRead(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, minted(t, c, "rid-silent", silentOrigin(t), silentOrigin(t), false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	if !a.Attests() || a.HandOver == nil {
		t.Fatalf("Attests %v, HandOver %v; want the request served whole", a.Attests(), a.HandOver)
	}
	stamps, ok := a.HandOver.Under(influence.Name)
	if !ok {
		t.Fatal("nothing is handed on under influence")
	}
	if d := influence.Decide(stamps, nil, false, "bob"); d.Reason != reason.OK || d.EveryStampNames {
		t.Fatalf("a read is %+v; want OK, with a stamp not naming influence", d)
	}
}

// TestAWriteAtAServiceNotActingOnInfluenceIsDenied: at a service whose settings do not act on influence, acting on
// nothing or on another extension, a guarded public write is denied and no trusted record is written, from a
// request whose chain verified with every stamp naming influence: a write-guarding service deployed without the
// extension is the mistake the rules exist to catch. The same request at a service acting on influence is allowed
// both.
func TestAWriteAtAServiceNotActingOnInfluenceIsDenied(t *testing.T) {
	c := verifiedCase(t)
	named := everyNaming(t, entryItem)
	other, err := verify.NewExtensions([]string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, ext := range map[string]verify.Extensions{"acting on nothing": {}, "acting on another": other} {
		t.Run(name, func(t *testing.T) {
			r := caseReceiver(t, c)
			r.Extensions, r.Verifier = ext, caseVerifierWith(t, c, ext)
			a := r.Accept(t.Context(), minted(t, c, "rid-named", named, named, false), nil, paztporthttp.ModeEnforce)
			wantServed(t, a, true)
			wantWrite(t, a, nil, "", reason.InfluenceDenied)
			wantWrite(t, a, []influence.Entry{privateRead("bob")}, "bob", reason.InfluenceDenied)
			wantRecord(t, a, nil, false)
		})
	}
	a := accept(t, c, minted(t, c, "rid-named", named, named, false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	wantWrite(t, a, nil, "", reason.OK)
	wantRecord(t, a, nil, true)
}

// TestWhatTheServiceReadCountsAgainstTheWrite: what the service read since it accepted the request counts beside
// what was handed on. Alice's private entry handed on is no bar to a write to bob alone, since nothing untrusted
// is held; a third-party read beside it is, though the write to alice, her own data, is still allowed. The same
// read bars a trusted record.
func TestWhatTheServiceReadCountsAgainstTheWrite(t *testing.T) {
	c := verifiedCase(t)
	blocks := everyNaming(t, privateItem)
	a := accept(t, c, minted(t, c, "rid-private", blocks, blocks, false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	read := []influence.Entry{thirdPartyRead}
	wantWrite(t, a, nil, "bob", reason.OK)
	wantWrite(t, a, read, "bob", reason.InfluenceDenied)
	wantWrite(t, a, read, "", reason.InfluenceDenied)
	wantWrite(t, a, read, "alice", reason.OK)
	wantRecord(t, a, nil, true)
	wantRecord(t, a, read, false)
}

// TestNothingHandedOnIsDecidedOnWhatWasAdded: where nothing was handed on, at an origin or where the chain did not
// read, the every-stamp rule has no stamp to read and holds, so a request whose origin block does not name
// influence, denied at a hop, is allowed a guarded write here; the owner-aware rule reads what the service read.
// No trusted record is written. The zero Accepted, work outside any request, has no settings, so it is denied.
func TestNothingHandedOnIsDecidedOnWhatWasAdded(t *testing.T) {
	c := ruleCase(t, "trustedRecord", "verified, only trusted entries, the origin's block not naming influence")
	origin := caseReceiver(t, c)
	origin.Origin, origin.Stamper.Origin = true, true
	atOrigin := origin.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeNone)
	noChain := caseRequest(t, c.Get("request"))
	noChain.Chain = ""
	for name, a := range map[string]paztporthttp.Accepted{
		"an origin":                 atOrigin,
		"a chain that did not read": accept(t, c, noChain, paztporthttp.ModeAudit),
	} {
		t.Run(name, func(t *testing.T) {
			wantServed(t, a, false)
			if a.HandOver != nil {
				t.Fatalf("HandOver %v, want nothing handed on", a.HandOver)
			}
			wantWrite(t, a, nil, "bob", reason.OK)
			wantWrite(t, a, []influence.Entry{thirdPartyRead, privateRead("alice")}, "bob", reason.InfluenceDenied)
			wantWrite(t, a, []influence.Entry{thirdPartyRead, privateRead("bob")}, "bob", reason.OK)
			wantRecord(t, a, nil, false)
		})
	}
	t.Run("work outside any request", func(t *testing.T) {
		var a paztporthttp.Accepted
		wantWrite(t, a, nil, "bob", reason.InfluenceDenied)
		wantRecord(t, a, nil, false)
	})
}

// TestATrustedRecordNeedsAVerifiedHandOverEveryStampNamingInfluenceAndNoUntrusted: a trusted record is written
// from a request only when its chain verified here, every stamp names influence, and neither what was handed on
// nor what the service read holds untrusted content. Served unverified on any path, an audit-mode failure among
// them, it is not, though a guarded write reads the items shown and may be allowed; nor with a pass-along origin
// block, nor after a local-untrusted read.
func TestATrustedRecordNeedsAVerifiedHandOverEveryStampNamingInfluenceAndNoUntrusted(t *testing.T) {
	c := verifiedCase(t)
	named := everyNaming(t, entryItem, privateItem)
	t.Run("verified", func(t *testing.T) {
		a := accept(t, c, minted(t, c, "rid-named", named, named, false), paztporthttp.ModeEnforce)
		wantServed(t, a, true)
		wantRecord(t, a, nil, true)
		wantRecord(t, a, []influence.Entry{publicRead, privateRead("bob")}, true)
		wantRecord(t, a, []influence.Entry{localUntrustedRead}, false)
		wantRecord(t, a, []influence.Entry{thirdPartyRead}, false)
	})
	for _, p := range unverifiedPaths {
		t.Run(p.name, func(t *testing.T) {
			a := p.receiver(t, c).Accept(t.Context(), minted(t, c, "rid-named", named, named, p.forged), nil, p.mode)
			wantServed(t, a, false)
			if a.HandOver == nil || a.HandOver.Verified() {
				t.Fatalf("HandOver %v, want the items handed on, not verified", a.HandOver)
			}
			wantRecord(t, a, nil, false)
			wantWrite(t, a, nil, "alice", reason.OK)
			wantWrite(t, a, []influence.Entry{thirdPartyRead}, "bob", reason.InfluenceDenied)
		})
	}
	t.Run("a pass-along origin block", func(t *testing.T) {
		passAlong, err := stamp.NewBlock(nil, []string{influence.Name})
		if err != nil {
			t.Fatal(err)
		}
		blocks := stamp.Blocks{passAlong, itemsBlock(t, entryItem)}
		a := accept(t, c, minted(t, c, "rid-pass-along", blocks, blocks, false), paztporthttp.ModeEnforce)
		wantServed(t, a, true)
		wantRecord(t, a, nil, false)
		wantWrite(t, a, nil, "", reason.InfluenceDenied)
	})
}

// TestAHandOverSetByHandIsReadOrDenied: HandOver is the embedder's to change, so the rules read whatever it holds.
// One holding an item that does not read, which Accept would have refused, is denied a write and a record, never
// allowed; one built under settings that do not act on influence holds nothing under it and is denied too, not
// read as nothing handed on.
func TestAHandOverSetByHandIsReadOrDenied(t *testing.T) {
	c := verifiedCase(t)
	named := everyNaming(t, entryItem)
	a := accept(t, c, minted(t, c, "rid-named", named, named, false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	unread := stamp.Blocks{itemsBlock(t), itemsBlock(t, `"not an entry"`)}
	a.HandOver = verify.NewHandOver(true, a.Inbound.Chain, unread, actsOnInfluence(t))
	wantWrite(t, a, nil, "", reason.InfluenceDenied)
	wantRecord(t, a, nil, false)
	a.HandOver = verify.NewHandOver(true, a.Inbound.Chain, named, verify.Extensions{})
	wantWrite(t, a, nil, "", reason.InfluenceDenied)
	wantRecord(t, a, nil, false)
}

// TestARefusedRequestIsDeniedEveryWrite: a request Accept refused is not served, so nothing a handler might still
// decide from it is allowed: no guarded write and no trusted record, even where its chain would otherwise allow
// both.
func TestARefusedRequestIsDeniedEveryWrite(t *testing.T) {
	c := verifiedCase(t)
	named := everyNaming(t, entryItem)
	a := accept(t, c, minted(t, c, "rid-forged", named, named, true), paztporthttp.ModeEnforce)
	wantRefused(t, a, 403, reason.BadSignature)
	wantWrite(t, a, nil, "", reason.InfluenceDenied)
	wantRecord(t, a, nil, false)
}

// FuzzAccept never panics on any request, and its answers keep the receiver's rules: a refusal is 400 or 403 and
// carries nothing, only a verified chain is attested or handed on as verified, a served chain carries one block
// per stamp, and an origin carries nothing.
func FuzzAccept(f *testing.F) {
	c := ruleCase(f, "trustedRecord", "verified, private and public with owners")
	r := c.Get("request")
	hs := r.Get("headers")
	body, _ := hex.DecodeString(r.Get("body").Str())
	chain, proof, blocks := hs.Get(wire.Chain).Str(), hs.Get(wire.Proof).Str(), hs.Get(wire.Extensions).Str()
	f.Add("POST", "/pay", chain, proof, blocks, body, 0, false)
	f.Add("POST", "/pay", chain, proof, blocks, body, 1, true)
	f.Add("POST", "/pay", chain, proof, "", body, 1, false)
	f.Add("POST", "/pay", chain, proof, blocks, body, 3, false)
	f.Add("POST", "/pay?", chain, "", "", body, 1, false)
	f.Add("GET", "/pay\xff", "W10", "ew", "W10", []byte(nil), 3, false)
	f.Add("", "", " \t", nbsp, "not*base64url", []byte{}, 2, true)
	f.Add("POST", "/pay", "", "", "e30", body, 1, false)
	f.Fuzz(func(t *testing.T, method, target, chain, proof, blocks string, body []byte, mode int, origin bool) {
		rc := caseReceiver(t, c.With(t))
		rc.Origin, rc.Stamper.Origin = origin, origin
		req := paztporthttp.InboundRequest{
			Method: method, Target: target, Chain: chain, Proof: proof, Extensions: blocks, Body: body,
		}
		a := rc.Accept(t.Context(), req, nil, paztporthttp.Mode(mode))
		carries := a.Inbound.Chain != nil || a.Inbound.Blocks != nil || a.HandOver != nil
		if a.Refusal != nil {
			if (a.Refusal.Status != 400 && a.Refusal.Status != 403) || a.Verified || a.Attests() || carries {
				t.Fatalf("refusal %+v with Verified %v, Attests %v, carrying %v", a.Refusal, a.Verified, a.Attests(),
					carries)
			}
			if !strings.HasPrefix(string(a.Refusal.Body), `{"reason":"`) {
				t.Fatalf("refusal body %s", a.Refusal.Body)
			}
		}
		if origin && (a.Verified || a.Attests() || carries) {
			t.Fatalf("an origin carried Verified %v, Attests %v, Inbound %+v, HandOver %v",
				a.Verified, a.Attests(), a.Inbound, a.HandOver)
		}
		if a.Attests() && !a.Verified {
			t.Fatal("an unverified chain is attested")
		}
		if a.HandOver != nil && a.HandOver.Verified() != a.Verified {
			t.Fatalf("a hand-over verified %v on a request verified %v", a.HandOver.Verified(), a.Verified)
		}
		if len(a.Inbound.Blocks) != len(a.Inbound.Chain) {
			t.Fatalf("Inbound carries %d blocks for %d stamps", len(a.Inbound.Blocks), len(a.Inbound.Chain))
		}
		if a.Attests() {
			if _, _, err := a.Attest(200, body, nil); err != nil {
				t.Fatalf("Attest: %v", err)
			}
		}
	})
}

// servePath is one way a receiver comes to serve a request without a verified chain: the receiver for case c
// and the mode it is given, and whether the chain must be forged, signed with another key, to get there.
type servePath struct {
	name     string
	mode     paztporthttp.Mode
	forged   bool
	receiver func(t *testing.T, c vectors.Node) *paztporthttp.Receiver
}

// unverifiedPaths are the receivers that serve a request without a verified chain (verification.md, A service
// never serves a request whose blocks fail check 9a): in audit mode with a nonce cache that cannot answer and
// after a failure, with Paztport off, with no verifier, with a verifier but no stamper, and under no mode with a
// nonce cache that cannot answer and after a failure.
var unverifiedPaths = []servePath{
	{"audit, the nonce cache down", paztporthttp.ModeAudit, false, downReceiver},
	{"audit, a bad signature", paztporthttp.ModeAudit, true, caseReceiver},
	{"off", paztporthttp.ModeOff, false, caseReceiver},
	{"no verifier", paztporthttp.ModeNone, false, func(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		r.Verifier = nil
		return r
	}},
	{"no stamper, no mode", paztporthttp.ModeNone, false, func(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		r.Stamper = nil
		return r
	}},
	{"no mode, the nonce cache down", paztporthttp.ModeNone, false, downReceiver},
	{"no mode, a forged chain", paztporthttp.ModeNone, true, caseReceiver},
}

// downReceiver is case c's receiver, its nonce cache down.
func downReceiver(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
	return failingReceiver(t, c, errors.New("the store is down"))
}

// TestABlockAlteredIsAnsweredFourHundredAtEveryUnverifiedServePath: a request whose chain reads, every ext "", but
// whose blocks header holds a block that names influence, is never served. Every receiver that would serve it
// unverified refuses it 400 EXTENSION_MISMATCH and attests nothing; enforce refuses it 403. Where the nonce cache
// is down, the live order refuses the blocks before it asks the cache, so the request is refused all the same.
func TestABlockAlteredIsAnsweredFourHundredAtEveryUnverifiedServePath(t *testing.T) {
	c := verifiedCase(t)
	altered := stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, entryItem)}
	for _, p := range unverifiedPaths {
		t.Run(p.name, func(t *testing.T) {
			req := minted(t, c, "rid-altered", empties(2), altered, p.forged)
			a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
			wantRefused(t, a, 400, reason.ExtensionMismatch)
		})
	}
	t.Run("enforce", func(t *testing.T) {
		req := minted(t, c, "rid-altered", empties(2), altered, false)
		wantRefused(t, accept(t, c, req, paztporthttp.ModeEnforce), 403, reason.ExtensionMismatch)
	})
}

// TestTheSameRequestIsServedAtAnOrigin: an origin carries neither the chain nor the blocks a request brings, so it
// has nothing to drop, and serves the request whose block was altered, carrying and handing on nothing.
func TestTheSameRequestIsServedAtAnOrigin(t *testing.T) {
	c := verifiedCase(t)
	req := minted(t, c, "rid-altered", empties(2), stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, entryItem)}, false)
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeAudit, paztporthttp.ModeNone, paztporthttp.ModeOff} {
		r := caseReceiver(t, c)
		r.Origin, r.Stamper.Origin = true, true
		a := r.Accept(t.Context(), req, nil, mode)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
	}
}

// TestBlocksThatMatchAreHandedOnAsNotVerifiedOnEachPath: on every path that serves a request without a verified
// chain, blocks that match their stamps are carried on as received and their items handed on, not verified.
func TestBlocksThatMatchAreHandedOnAsNotVerifiedOnEachPath(t *testing.T) {
	c := verifiedCase(t)
	blocks := stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, entryItem)}
	want := []verify.StampItems{{Svc: "gateway"}, {Svc: "orders", Named: true, Items: []string{entryItem}}}
	for _, p := range unverifiedPaths {
		t.Run(p.name, func(t *testing.T) {
			req := minted(t, c, "rid-matching", blocks, blocks, p.forged)
			a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
			wantServed(t, a, false)
			if a.Attests() || a.HandOver == nil || a.HandOver.Verified() {
				t.Fatalf("Attests %v, HandOver %v; want the items handed on, not verified, unattested",
					a.Attests(), a.HandOver)
			}
			handover.Match(t, "handed on", a.HandOver, map[string][]verify.StampItems{influence.Name: want})
			if len(a.Inbound.Chain) != 2 || blocksHeader(t, a.Inbound.Blocks) != req.Extensions {
				t.Fatalf("Inbound %+v, want the chain and the blocks as received", a.Inbound)
			}
		})
	}
}

// TestNoChainWithBlocksThatAreAnObjectIsFourHundred: where the chain did not read, blocks still have to read as an
// array of blocks, so blocks that are an object are refused 400 EXTENSION_MISMATCH on every path that serves
// without verifying; enforce refuses the missing chain first.
func TestNoChainWithBlocksThatAreAnObjectIsFourHundred(t *testing.T) {
	c := verifiedCase(t)
	for _, chain := range []string{"", "not*base64url"} {
		req := caseRequest(t, c.Get("request"))
		req.Chain, req.Extensions = chain, "e30" // {}
		for _, p := range unverifiedPaths {
			if p.forged {
				continue
			}
			wantRefused(t, p.receiver(t, c).Accept(t.Context(), req, nil, p.mode), 400, reason.ExtensionMismatch)
		}
		wantRefused(t, accept(t, c, req, paztporthttp.ModeEnforce), 403, reason.ChainMissing)
	}
}

// TestNoChainWithBlocksThatAreAnArrayIsServedWithNothing: where the chain did not read, blocks that read as an
// array are served, with nothing carried and nothing handed on.
func TestNoChainWithBlocksThatAreAnArrayIsServedWithNothing(t *testing.T) {
	c := verifiedCase(t)
	for _, blocks := range []string{"W10", header(c, wire.Extensions), ""} { // [], two blocks, none
		req := caseRequest(t, c.Get("request"))
		req.Chain, req.Extensions = "", blocks
		for _, p := range unverifiedPaths {
			if p.forged {
				continue
			}
			a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
			wantServed(t, a, false)
			wantNothingCarried(t, a)
		}
	}
}

// TestAVerifiedRequestHandsOverTheVerifiersHandOver: a chain that passed the live order is handed on as verified,
// with the verifier's own hand-over, and carries the blocks received.
func TestAVerifiedRequestHandsOverTheVerifiersHandOver(t *testing.T) {
	c := influenceCase(t)
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit, paztporthttp.ModeNone} {
		a := accept(t, c, caseRequest(t, c.Get("request")), mode)
		wantServed(t, a, true)
		if a.HandOver == nil || !a.HandOver.Verified() || a.Result == nil || a.HandOver != a.Result.HandOver {
			t.Fatalf("%v: HandOver %v, Result %+v; want the verifier's hand-over", mode, a.HandOver, a.Result)
		}
		handover.Match(t, mode.String(), a.HandOver, handover.Expected(t, c.Get("expected").Get("handedOn").Raw()))
		if blocksHeader(t, a.Inbound.Blocks) != header(c, wire.Extensions) {
			t.Fatalf("%v: Inbound.Blocks %+v, want the blocks received", mode, a.Inbound.Blocks)
		}
	}
}

// TestABlocksHeaderThatDoesNotDecodeIsExtensionMismatch: a blocks header present that does not decode is check
// 9a's failure, 403 in enforce mode and 400 on every other path, never one empty block per stamp.
func TestABlocksHeaderThatDoesNotDecodeIsExtensionMismatch(t *testing.T) {
	c := verifiedCase(t)
	for _, blocks := range []string{"not*base64url", "bnVsbA", "W3t9XQ"} { // not base64url, null, [{}]
		req := minted(t, c, "rid-undecoded", empties(2), nil, false)
		req.Extensions = blocks
		wantRefused(t, accept(t, c, req, paztporthttp.ModeEnforce), 403, reason.ExtensionMismatch)
		for _, p := range unverifiedPaths {
			req := minted(t, c, "rid-undecoded", empties(2), nil, p.forged)
			req.Extensions = blocks
			wantRefused(t, p.receiver(t, c).Accept(t.Context(), req, nil, p.mode), 400, reason.ExtensionMismatch)
		}
	}
}

// TestNoBlocksHeaderIsOneEmptyBlockPerStamp: with no blocks header every block is empty, so a chain whose every
// ext is "" verifies, and is carried on with one empty block per stamp, nothing named in the hand-over.
func TestNoBlocksHeaderIsOneEmptyBlockPerStamp(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, minted(t, c, "rid-none", empties(2), nil, false), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	if len(a.Inbound.Blocks) != 2 || a.Inbound.Blocks[0].Commit() != "" || a.Inbound.Blocks[1].Commit() != "" {
		t.Fatalf("Inbound.Blocks %+v, want two empty blocks", a.Inbound.Blocks)
	}
	handover.Match(t, "handed on", a.HandOver,
		map[string][]verify.StampItems{influence.Name: {{Svc: "gateway"}, {Svc: "orders"}}})
}

// TestABlankBlocksHeaderIsNoHeader: a blocks header that is present but blank, nothing but HTTP's optional
// whitespace, is read as no header, so a chain whose every ext is "" is served, verified, as with none.
func TestABlankBlocksHeaderIsNoHeader(t *testing.T) {
	c := verifiedCase(t)
	for _, blank := range []string{"", " ", " \t "} {
		base := minted(t, c, "rid-blank", empties(2), nil, false)
		req := withHeaders(t, c, map[string][]string{
			wire.Chain: {base.Chain}, wire.Proof: {base.Proof}, wire.Extensions: {blank},
		})
		for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit} {
			a := accept(t, c, req, mode)
			wantServed(t, a, true)
			if a.Result == nil || !a.Result.OK() || len(a.Inbound.Blocks) != 2 {
				t.Fatalf("%q, %v: Result %+v, Inbound %+v; want OK with two empty blocks", blank, mode, a.Result,
					a.Inbound)
			}
		}
	}
}

// itemPaths are receivers that verify a request or serve it unverified, each in a mode: whether the chain is
// forged, and whether the request is then verified.
var itemPaths = []struct {
	servePath
	verified bool
}{
	{servePath{"enforce", paztporthttp.ModeEnforce, false, caseReceiver}, true},
	{servePath{"audit", paztporthttp.ModeAudit, false, caseReceiver}, true},
	{servePath{"no mode", paztporthttp.ModeNone, false, caseReceiver}, true},
	{unverifiedPaths[0], false},
	{unverifiedPaths[1], false},
	{unverifiedPaths[2], false},
	{unverifiedPaths[3], false},
	{unverifiedPaths[4], false},
	{unverifiedPaths[5], false},
	{unverifiedPaths[6], false},
}

// TestAnItemThatDoesNotReadIsFourHundredAtAServiceActingOnInfluence: a service whose settings act on influence
// refuses a request handed an influence item that does not read as an entry, 400 INFLUENCE_MISMATCH, whether its
// chain verified or not, in every mode.
func TestAnItemThatDoesNotReadIsFourHundredAtAServiceActingOnInfluence(t *testing.T) {
	c := verifiedCase(t)
	blocks := stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, `"not an entry"`)}
	for _, p := range itemPaths {
		t.Run(p.name, func(t *testing.T) {
			req := minted(t, c, "rid-unread", blocks, blocks, p.forged)
			a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
			wantRefused(t, a, 400, reason.InfluenceMismatch)
		})
	}
}

// TestTheSameItemIsServedAtAServiceNotActingOnInfluence: a service whose settings do not act on influence reads no
// item, so it serves the same request, verified where its chain verifies, handing nothing on under influence.
func TestTheSameItemIsServedAtAServiceNotActingOnInfluence(t *testing.T) {
	c := ruleCase(t, "influenceItems", "enforce, at a service that does not act on influence")
	blocks := stamp.Blocks{stamp.EmptyBlock, itemsBlock(t, `"not an entry"`)}
	for _, p := range itemPaths {
		t.Run(p.name, func(t *testing.T) {
			req := minted(t, c, "rid-unread", blocks, blocks, p.forged)
			a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
			wantServed(t, a, p.verified)
			if a.HandOver == nil || len(a.HandOver.Names()) != 0 || len(a.Inbound.Blocks) != 2 {
				t.Fatalf("HandOver %v, Inbound %+v; want nothing named and the blocks carried", a.HandOver,
					a.Inbound)
			}
		})
	}
}

// TestReceiverSettingsBesideAVerifierWithOthersPanic: a receiver states its settings once, so settings beside a
// verifier that hold others panic, a fault in the program, in every mode; the verifier's own do not.
func TestReceiverSettingsBesideAVerifierWithOthersPanic(t *testing.T) {
	c := verifiedCase(t)
	carriesNothing, err := verify.NewExtensionsAllowing(nil, []string{})
	if err != nil {
		t.Fatal(err)
	}
	example, err := verify.NewExtensions([]string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		given  verify.Extensions
		panics bool
	}{
		"the verifier's own": {caseSettings(t, c), false},
		"a list of nothing":  {carriesNothing, true},
		"acting on another":  {example, true},
		"the zero settings":  {verify.Extensions{}, false},
	} {
		for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeOff} {
			func() {
				r := caseReceiver(t, c)
				r.Extensions = tc.given
				defer func() {
					if got := recover() != nil; got != tc.panics {
						t.Errorf("%s, %v: panicked %v, want %v", name, mode, got, tc.panics)
					}
				}()
				r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
			}()
		}
	}
}

// TestZeroSettingsBesideAVerifierTakeTheVerifiers: zero settings beside a verifier state nothing, so the verifier's
// own decide what is handed on; with no verifier, zero settings act on nothing.
func TestZeroSettingsBesideAVerifierTakeTheVerifiers(t *testing.T) {
	c := influenceCase(t)
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeOff} {
		r := caseReceiver(t, c)
		r.Extensions = verify.Extensions{}
		a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
		wantServed(t, a, mode == paztporthttp.ModeEnforce)
		if a.HandOver == nil || !slices.Equal(a.HandOver.Names(), []string{influence.Name}) {
			t.Fatalf("%v: HandOver %v, want the verifier's settings, acting on influence", mode, a.HandOver)
		}
	}
	r := caseReceiver(t, c)
	r.Verifier, r.Extensions = nil, verify.Extensions{}
	a := r.Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeNone)
	wantServed(t, a, false)
	if a.HandOver == nil || len(a.HandOver.Names()) != 0 {
		t.Fatalf("HandOver %v, want nothing named", a.HandOver)
	}
}

// TestTheRequestNonceKeyIsAJCSArray spends the JCS text of [rid, last svc, last rcv, "req"], so no part can run
// into the next: the request whose rid is "a|orders" does not spend the key of the keyed request whose rid is "a",
// which a key joining its parts with "|" would make the same text, and is a replay only of itself.
func TestTheRequestNonceKeyIsAJCSArray(t *testing.T) {
	c := verifiedCase(t)
	req := minted(t, c, "a|orders", empties(2), nil, false)
	receiverOver := func(cache verify.NonceCache) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		now := c.Get("now").Int()
		r.Verifier = pinnedVerifier(t, "shop", verify.Config{
			AllowedOrigins: []string{"gateway"},
			Nonces:         cache,
			Now:            func() int64 { return now },
			CallMaxAgeMs:   verify.CallMaxAgeMs,
			RunMaxAgeMs:    verify.RunMaxAgeMs,
			Extensions:     caseSettings(t, c),
		})
		return r
	}
	recorded := newRecordingNonces()
	wantServed(t, receiverOver(recorded).Accept(t.Context(), req, nil, paztporthttp.ModeEnforce), true)
	own := `["a|orders","orders","payment","req"]`
	if !slices.Equal(recorded.asked, []string{own}) {
		t.Fatalf("nonce keys %q, want %q", recorded.asked, own)
	}
	for _, tc := range []struct {
		spent  string
		replay bool
	}{
		{wire.RequestNonceKey("a", "orders", "orders", "payment"), false},
		{"a|orders|orders|payment|req", false},
		{own, true},
	} {
		cache := verify.NewMemoryNonceCache(verify.NonceTTLMs)
		if _, err := cache.SeenBefore(t.Context(), tc.spent, c.Get("now").Int()); err != nil {
			t.Fatal(err)
		}
		a := receiverOver(cache).Accept(t.Context(), req, nil, paztporthttp.ModeEnforce)
		if tc.replay {
			wantRefused(t, a, 403, reason.Replay)
			continue
		}
		wantServed(t, a, true)
	}
}

// TestARIDHoldingALoneSurrogateEscapeDoesNotRead: a chain whose rid holds a lone surrogate escape does not read,
// so it is CHAIN_MISSING and no nonce key is made from it, and Accept answers in every mode without a panic.
func TestARIDHoldingALoneSurrogateEscapeDoesNotRead(t *testing.T) {
	c := verifiedCase(t)
	req := minted(t, c, "rid-surrogate", empties(2), nil, false)
	text, err := b64.Decode(req.Chain)
	if err != nil {
		t.Fatal(err)
	}
	escaped := strings.ReplaceAll(string(text), `"rid":"rid-surrogate"`, `"rid":"\ud800"`)
	if escaped == string(text) {
		t.Fatal("the chain's rid was not replaced")
	}
	req.Chain = b64.Encode([]byte(escaped))
	wantRefused(t, accept(t, c, req, paztporthttp.ModeEnforce), 403, reason.ChainMissing)
	for _, p := range unverifiedPaths {
		a := p.receiver(t, c).Accept(t.Context(), req, nil, p.mode)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
	}
}
