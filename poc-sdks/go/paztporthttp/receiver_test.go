// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
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

// verifiedCase is a request that verifies at payment, enforced, with no influence; influenceCase is one
// with the influence its last stamp commits to.
func verifiedCase(t testing.TB) vectors.Node  { return ruleCase(t, "requests", "verified") }
func influenceCase(t testing.TB) vectors.Node { return ruleCase(t, "attestation", "enforce, verified") }

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

// wantRefused fails t unless a is refused with status and code, and nothing else.
func wantRefused(t *testing.T, a paztporthttp.Accepted, status int, code reason.Code) {
	t.Helper()
	if a.Refusal == nil {
		t.Fatalf("served (Verified %v), want %d %s", a.Verified, status, code)
	}
	want := `{"reason":"` + string(code) + `"}`
	if a.Refusal.Status != status || string(a.Refusal.Body) != want {
		t.Fatalf("refused %d %s, want %d %s", a.Refusal.Status, a.Refusal.Body, status, want)
	}
	if a.Verified || a.Attests() || a.Inbound != nil || len(a.Influence) != 0 {
		t.Fatalf("a refusal carries Verified %v, Attests %v, Inbound %v, Influence %v",
			a.Verified, a.Attests(), a.Inbound, a.Influence)
	}
}

// TestAcceptChainHeaderValues reads the chain header as the spec reads a header: blank is absent, only
// SP and HTAB around the token are trimmed, and of two values the first counts.
func TestAcceptChainHeaderValues(t *testing.T) {
	c := verifiedCase(t)
	tok, proof := header(c, wire.Chain), header(c, wire.Proof)
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
			req := withHeaders(t, c, map[string][]string{wire.Chain: tt.values, wire.Proof: {proof}})
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
	chain, proof := header(c, wire.Chain), header(c, wire.Proof)
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
			req := withHeaders(t, c, map[string][]string{wire.Chain: {chain}, wire.Proof: tt.values})
			a := accept(t, c, req, paztporthttp.ModeEnforce)
			if tt.ok {
				wantServed(t, a, true)
				return
			}
			wantRefused(t, a, 403, reason.PathNotAllowed)
		})
	}
}

// TestAcceptInfluenceHeaderValues reads the influence header the same way. In audit mode a request
// whose influence does not read is refused 400, while a blank one is absent: no entries, which the last
// stamp does not commit to, so the request is served unverified.
func TestAcceptInfluenceHeaderValues(t *testing.T) {
	c := influenceCase(t)
	chain, proof, infl := header(c, wire.Chain), header(c, wire.Proof), header(c, wire.Influence)
	want := entries(c.Get("expected").Get("influence"))
	tests := []struct {
		name   string
		values []string
		want   string // verified, unverified or unreadable
	}{
		{"as sent", []string{infl}, "verified"},
		{"absent", nil, "unverified"},
		{"blank", []string{""}, "unverified"},
		{"whitespace only", []string{" "}, "unverified"},
		{"a leading HTAB and a trailing SP", []string{"\t" + infl + " "}, "verified"},
		{"a trailing U+00A0", []string{infl + nbsp}, "unreadable"},
		{"two values, the first the influence", []string{infl, "not*base64url"}, "verified"},
		{"two values, the second the influence", []string{"not*base64url", infl}, "unreadable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string][]string{wire.Chain: {chain}, wire.Proof: {proof}, wire.Influence: tt.values}
			a := accept(t, c, withHeaders(t, c, values), paztporthttp.ModeAudit)
			switch tt.want {
			case "verified":
				wantServed(t, a, true)
				if !slices.Equal(a.Influence, want) {
					t.Fatalf("Influence = %+v, want %+v", a.Influence, want)
				}
			case "unverified":
				wantServed(t, a, false)
				if len(a.Influence) != 0 || a.Result == nil || a.Result.Reason != reason.InfluenceMismatch {
					t.Fatalf("Influence %+v, Result %+v, want none and INFLUENCE_MISMATCH", a.Influence, a.Result)
				}
			default:
				wantRefused(t, a, 400, reason.InfluenceMismatch)
			}
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
	h.Add("X-Path-Session", "")
	h.Add("X-Path-Session", "sess-2")
	h.Add("X-Path-Response", "not read")
	body := []byte("body")
	got := paztporthttp.NewInboundRequest("POST", "/pay?x=%C3%A9", body, h.Values)
	if got.Method != "POST" || got.Target != "/pay?x=%C3%A9" || got.Chain != "chain-1" || got.Proof != "proof-1" ||
		got.Influence != "" || got.Session != "" || &got.Body[0] != &body[0] {
		t.Fatalf("NewInboundRequest = %+v", got)
	}

	var asked []string
	paztporthttp.NewInboundRequest("GET", "/", nil, func(name string) []string {
		asked = append(asked, name)
		return nil
	})
	slices.Sort(asked)
	if wantAsked := []string{wire.Chain, wire.Influence, wire.Proof, wire.Session}; !slices.Equal(asked, wantAsked) {
		t.Fatalf("looked up %q, want %q", asked, wantAsked)
	}

	if got := paztporthttp.NewInboundRequest("GET", "/", nil, nil); got.Chain != "" || got.Proof != "" ||
		got.Influence != "" || got.Session != "" {
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

// TestAttestRoundTrip attests a verified request's answer, and the caller's check of the header, with
// the chain and proof it sent, verifies it with its labels. What the handler does to Inbound does not
// change what is vouched for.
func TestAttestRoundTrip(t *testing.T) {
	c := influenceCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	sent := slices.Clone(a.Inbound)
	a.Inbound[len(a.Inbound)-1].Svc = "elsewhere"
	a.Inbound = a.Inbound[:1]

	labels := []influence.Label{
		influence.NewLabel(influence.Private, "alice"),
		{Class: influence.Public, CID: "cid-catalogue"},
	}
	body := []byte(`{"paid":true}`)
	h, ok, err := a.Attest(201, body, labels)
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
	check, err := wire.CheckResponse(t.Context(), caller, sent, &proof, h, 201, body, "orders")
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	if !check.Result.OK() || check.Result.SuspectSvc != "payment" || check.Result.SuspectInst != "pay-1" {
		t.Fatalf("the caller's check = %+v, want OK from payment@pay-1", check.Result)
	}
	if !slices.Equal(check.Labels, labels) {
		t.Fatalf("Labels = %+v, want %+v", check.Labels, labels)
	}
	for _, other := range []struct {
		status int
		body   string
	}{{200, `{"paid":true}`}, {201, `{"paid":false}`}} {
		check, err := wire.CheckResponse(t.Context(), caller, sent, &proof, h, other.status, []byte(other.body), "orders")
		if err != nil || check.Result.Reason != reason.BindingMismatch {
			t.Fatalf("another answer (%d %s) checks as %+v, %v", other.status, other.body, check.Result, err)
		}
	}
}

// TestAttestUnattested gives no header for an answer that is not attested, or whose binding cannot carry
// the request's rid or a label, and an error only for a stamper that cannot sign.
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
	t.Run("a label the binding cannot carry", func(t *testing.T) {
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
		req := caseRequest(t, c.Get("request"))
		req.Chain = mintedChain(t, c, "rid\nrules", req)
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

// mintedChain returns the token of a chain gateway then orders sign for req at payment, at case c's now,
// in the request rid.
func mintedChain(t *testing.T, c vectors.Node, rid string, req paztporthttp.InboundRequest) string {
	t.Helper()
	now := c.Get("now").Int()
	gwKey, _ := vectors.RulesKey(t, "gateway")
	ordKey, _ := vectors.RulesKey(t, "orders")
	gw := &stamp.Stamper{Svc: "gateway", Inst: "gw-1", Key: gwKey, Origin: true,
		NewRID: func() string { return rid }, Now: func() int64 { return now - 1500 }}
	ord := &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: ordKey, Now: func() int64 { return now - 500 }}
	first, _, err := gw.Next(nil, "orders", "bind-gateway-to-orders", nil, policy.ProofBundle{})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	bind, err := wire.Bind(req.Method, req.Target, req.Body)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	chain, _, err := ord.Next(first, "payment", bind, nil, policy.ProofBundle{})
	if err != nil {
		t.Fatalf("orders: %v", err)
	}
	tok, err := wire.EncodeChain(chain)
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	return tok
}

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
		if a.Result == nil || a.Result.Reason != reason.BadSignature || !a.Audit || a.Inbound == nil {
			t.Fatalf("Result %+v, Audit %v, Inbound %v", a.Result, a.Audit, a.Inbound)
		}
	})
	t.Run("audit, unreadable influence", func(t *testing.T) {
		c := ruleCase(t, "unreadableInfluence", "audit, on a chain that verifies otherwise")
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeAudit)
		wantRefused(t, a, 400, reason.InfluenceMismatch)
		if a.Result == nil || a.Result.Reason != reason.InfluenceMismatch || !a.Audit {
			t.Fatalf("Result %+v, Audit %v", a.Result, a.Audit)
		}
	})
	t.Run("off", func(t *testing.T) {
		c := verifiedCase(t)
		a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeOff)
		wantServed(t, a, false)
		if a.Result != nil || a.Audit || a.Inbound == nil {
			t.Fatalf("Result %+v, Audit %v, Inbound %v; want the chain carried and nothing verified",
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
	})
	return r
}

// TestAcceptCacheError decides a request whose nonce cache cannot answer: enforce refuses it 503 with
// no body, and audit and no mode serve it unverified and unattested; either way the cache's error is
// exposed, and nothing is carried, verified, attested or delivered. ctx reaches the cache.
func TestAcceptCacheError(t *testing.T) {
	c := verifiedCase(t)
	down := errors.New("the store is down")
	for _, mode := range []paztporthttp.Mode{paztporthttp.ModeEnforce, paztporthttp.ModeAudit, paztporthttp.ModeNone} {
		a := failingReceiver(t, c, down).Accept(t.Context(), caseRequest(t, c.Get("request")), nil, mode)
		if !errors.Is(a.CacheErr, down) {
			t.Fatalf("%v: CacheErr = %v, want the cache's", mode, a.CacheErr)
		}
		if mode == paztporthttp.ModeEnforce {
			if a.Refusal == nil || a.Refusal.Status != 503 || len(a.Refusal.Body) != 0 {
				t.Fatalf("%v: Refusal = %+v, want 503 and no body", mode, a.Refusal)
			}
		} else if a.Refusal != nil {
			t.Fatalf("%v: Refusal = %+v, want the request served", mode, a.Refusal)
		}
		if _, ok := a.Delivery(); ok || a.Verified || a.Attests() || a.Inbound != nil || a.Influence != nil ||
			a.Result != nil {
			t.Fatalf("%v: Accepted = %+v with the error, want nothing carried or verified", mode, a)
		}
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
	})
	a := r.Accept(ctx, caseRequest(t, c.Get("request")), nil, paztporthttp.ModeEnforce)
	if !errors.Is(a.CacheErr, context.Canceled) {
		t.Fatalf("CacheErr = %v, want the cancelled context's", a.CacheErr)
	}
}

// TestUnavailable is 503 and no body.
func TestUnavailable(t *testing.T) {
	if a := paztporthttp.Unavailable(); a.Status != 503 || len(a.Body) != 0 {
		t.Fatalf("Unavailable = %+v", a)
	}
}

// TestAcceptDelivery names the delivery of a request verified at this hop, from its first stamp's rid and
// its last stamp's signer and binding, and of no other.
func TestAcceptDelivery(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	d, ok := a.Delivery()
	last := a.Inbound[len(a.Inbound)-1]
	want := paztporthttp.Delivery{RID: a.Inbound[0].RID, Svc: last.Svc, Bind: last.Bind}
	if !ok || d != want || d.RID == "" || d.Svc == "" || d.Bind == "" {
		t.Fatalf("Delivery = %+v, %v; want %+v", d, ok, want)
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

// TestAcceptOrigin starts the request tree afresh: an origin carries neither the chain nor the
// influence, unreadable influence included, never takes the chain as verified and never attests. Under a
// mode it still runs the live order: enforce refuses a request that fails it, and audit reports it.
func TestAcceptOrigin(t *testing.T) {
	origin := func(t *testing.T, c vectors.Node) *paztporthttp.Receiver {
		r := caseReceiver(t, c)
		r.Origin, r.Stamper.Origin = true, true
		return r
	}
	wantNothingCarried := func(t *testing.T, a paztporthttp.Accepted) {
		t.Helper()
		if a.Verified || a.Attests() || a.Inbound != nil || a.Influence != nil {
			t.Fatalf("Verified %v, Attests %v, Inbound %v, Influence %v; want nothing carried",
				a.Verified, a.Attests(), a.Inbound, a.Influence)
		}
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
	t.Run("audit, unreadable influence", func(t *testing.T) {
		c := ruleCase(t, "unreadableInfluence", "audit, on a chain that verifies otherwise")
		a := origin(t, c).Accept(t.Context(), caseRequest(t, c.Get("request")), nil, paztporthttp.ModeAudit)
		wantServed(t, a, false)
		wantNothingCarried(t, a)
		if a.Result == nil || a.Result.Reason != reason.InfluenceMismatch || !a.Audit {
			t.Fatalf("Result %+v, Audit %v", a.Result, a.Audit)
		}
	})
	t.Run("no mode or off verifies nothing", func(t *testing.T) {
		c := ruleCase(t, "unreadableInfluence", "an origin carries none, so has none to drop")
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

// TestTrustedRecordLeavesInfluence never writes the handler's reads into the spare room of the
// Accepted's influence.
func TestTrustedRecordLeavesInfluence(t *testing.T) {
	clean := influence.Entry{Class: influence.Public, Src: "http:catalogue", H: "h-1"}
	backing := make([]influence.Entry, 1, 4)
	backing[0] = clean
	a := paztporthttp.Accepted{Verified: true, Influence: backing}
	read := []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-2"}}
	if a.TrustedRecord(read) {
		t.Fatal("a third-party read is trusted")
	}
	if spare := backing[:2][1]; spare != (influence.Entry{}) {
		t.Fatalf("TrustedRecord wrote %+v past the influence it was given", spare)
	}
	if !a.TrustedRecord(nil) || (paztporthttp.Accepted{Influence: backing}).TrustedRecord(nil) {
		t.Fatal("TrustedRecord does not follow Verified")
	}
}

// TestPartnerTrustedRecordLeavesTheInfluenceBackingAlone: TrustedRecord on an attested call never writes the
// reads into the spare room of the influence slice it was given.
func TestPartnerTrustedRecordLeavesTheInfluenceBackingAlone(t *testing.T) {
	backing := make([]influence.Entry, 1, 4)
	backing[0] = influence.Entry{Class: influence.Public, Src: "http:catalogue", H: "h-1"}
	p := paztporthttp.PartnerAccepted{Attested: true, Influence: backing}
	read := []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-2"}}
	p.TrustedRecord(read)
	if spare := backing[:2][1]; spare != (influence.Entry{}) {
		t.Fatalf("TrustedRecord wrote %+v past the influence it was given", spare)
	}
}

// FuzzAccept never panics on any request, and its answers keep the receiver's rules: a refusal is 400 or
// 403 and carries nothing, only a verified chain is attested, and an origin carries nothing.
func FuzzAccept(f *testing.F) {
	c := vectors.Rules(f).Get("attestation").Index(0)
	r := c.Get("request")
	hs := r.Get("headers")
	body, _ := hex.DecodeString(r.Get("body").Str())
	f.Add("POST", "/pay", hs.Get(wire.Chain).Str(), hs.Get(wire.Proof).Str(), hs.Get(wire.Influence).Str(), body, 0, false)
	f.Add("POST", "/pay", hs.Get(wire.Chain).Str(), hs.Get(wire.Proof).Str(), hs.Get(wire.Influence).Str(), body, 1, true)
	f.Add("POST", "/pay?", hs.Get(wire.Chain).Str(), "", "", body, 1, false)
	f.Add("GET", "/pay\xff", "W10", "ew", "W10", []byte(nil), 3, false)
	f.Add("", "", " \t", nbsp, "not*base64url", []byte{}, 2, true)
	f.Fuzz(func(t *testing.T, method, target, chain, proof, infl string, body []byte, mode int, origin bool) {
		rc := caseReceiver(t, c.With(t))
		rc.Origin, rc.Stamper.Origin = origin, origin
		req := paztporthttp.InboundRequest{
			Method: method, Target: target, Chain: chain, Proof: proof, Influence: infl, Body: body,
		}
		a := rc.Accept(t.Context(), req, nil, paztporthttp.Mode(mode))
		if a.Refusal != nil {
			if (a.Refusal.Status != 400 && a.Refusal.Status != 403) || a.Verified || a.Attests() || a.Inbound != nil {
				t.Fatalf("refusal %+v with Verified %v, Attests %v", a.Refusal, a.Verified, a.Attests())
			}
			if !strings.HasPrefix(string(a.Refusal.Body), `{"reason":"`) {
				t.Fatalf("refusal body %s", a.Refusal.Body)
			}
		}
		if origin && (a.Verified || a.Attests() || a.Inbound != nil || a.Influence != nil) {
			t.Fatalf("an origin carried Verified %v, Attests %v, Inbound %v, Influence %v",
				a.Verified, a.Attests(), a.Inbound, a.Influence)
		}
		if a.Attests() && !a.Verified {
			t.Fatal("an unverified chain is attested")
		}
		if a.Attests() {
			if _, _, err := a.Attest(200, body, nil); err != nil {
				t.Fatalf("Attest: %v", err)
			}
		}
	})
}
