// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"fmt"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestPartnerRulesVectors replays the partner kinds of http-v3.json's rules: each case runs its steps
// against one partner, its clock set to each step's at. A handshake is served by Sessions.ServeHandshake; a call is
// decided by Sessions.Accept, and then, as an adapter does, an unsafe session's switched-off operations
// are refused before the handler runs.
func TestPartnerRulesVectors(t *testing.T) {
	kinds := []struct {
		name  string
		cases int
	}{
		{"sessionHeader", 9}, {"sessionRegistry", 6}, {"handshakeErrors", 14}, {"sessionExpiry", 3},
		{"boundaryRefusals", 6},
	}
	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			cases := vectors.Rules(t).Get(kind.name)
			if cases.Len() != kind.cases {
				t.Fatalf("the rules have %d %s cases, want %d", cases.Len(), kind.name, kind.cases)
			}
			cases.Each(func(name string, c vectors.Node) {
				t.Run(name, func(t *testing.T) {
					runPartnerScript(t, c.With(t))
				})
			})
		})
	}
}

// partnerScript is one partner case running: the partner, its clock and the sessions its handshakes
// opened, by the names the case gives them.
type partnerScript struct {
	sessions *paztporthttp.Sessions
	disabled paztporthttp.UnsafeOperations
	now      int64
	opened   map[string]string
}

// runPartnerScript runs partner case c's steps in order and fails t at the first whose outcome is not
// its expected.
func runPartnerScript(t *testing.T, c vectors.Node) {
	t.Helper()
	p := c.Get("partner")
	sc := &partnerScript{now: p.Get("start").Int(), opened: map[string]string{}}
	cfg := partnerConfig(t, p, func() int64 { return sc.now })
	sc.disabled = paztporthttp.UnsafeOperations(cfg.UnsafeDisabled)
	s, err := paztporthttp.NewSessions(cfg)
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	sc.sessions = s
	steps := c.Get("steps")
	if steps.Len() == 0 {
		t.Fatal("the case has no steps")
	}
	for i := range steps.Len() {
		step := steps.Index(i)
		sc.now = step.Get("at").Int()
		var got, want string
		if step.Has("handshake") {
			got = sc.handshake(t, step)
			want = expectedHandshake(step.Get("expected"))
		} else {
			got = sc.call(t, step.Get("call"))
			want = expectedCall(t, step.Get("expected"))
		}
		if got != want {
			t.Fatalf("step %d: got %s\nwant %s", i, got, want)
		}
	}
}

// partnerConfig returns the configuration partner p describes, its material read from its files' text by
// the SDK's own readers, with clock now and a nonce cache of its own.
func partnerConfig(t testing.TB, p vectors.Node, now func() int64) paztporthttp.SessionsConfig {
	t.Helper()
	m := vectors.RulesMaterial(t, p.Get("material").Str())
	kf, err := policy.ParseKeyringFile(m.Keyring)
	if err != nil {
		t.Fatalf("ParseKeyringFile: %v", err)
	}
	root, err := policy.ParseRootFile(m.Root)
	if err != nil {
		t.Fatalf("ParseRootFile: %v", err)
	}
	cert, err := policy.ParseReplyCertFile(m.ReplyCert)
	if err != nil {
		t.Fatalf("ParseReplyCertFile: %v", err)
	}
	_, policyPub := vectors.RulesKey(t, m.PolicyKey)
	entryKey, _ := vectors.RulesKey(t, m.Entry)
	var pinned []string
	for _, name := range p.Get("pinned").Strs() {
		_, pub := vectors.RulesKey(t, name)
		pinned = append(pinned, keys.EncodePublic(pub))
	}
	return paztporthttp.SessionsConfig{
		Root:           root,
		Keyring:        kf,
		PolicyKey:      keys.EncodePublic(policyPub),
		Entry:          m.Entry,
		EntryKey:       entryKey,
		ReplyCert:      cert,
		Pinned:         pinned,
		ClientOrigins:  p.Get("clientOrigins").Strs(),
		UnsafeDisabled: p.Get("unsafeDisabled").Strs(),
		MaxPerPeer:     int(p.Get("maxSessionsPerPeer").Int()),
		IdleMs:         p.Get("sessionIdleMs").Int(),
		CallMaxAgeMs:   p.Get("callMaxAgeMs").Int(),
		RunMaxAgeMs:    p.Get("runMaxAgeMs").Int(),
		Nonces:         verify.NewMemoryNonceCache(p.Get("nonceTtlMs").Int()),
		Now:            now,
	}
}

// handshake posts a handshake step's body as the peer it names, records the session it opens under the
// step's as, and returns its outcome in the shape of expectedHandshake.
func (sc *partnerScript) handshake(t *testing.T, step vectors.Node) string {
	t.Helper()
	h := step.Get("handshake")
	var body []byte
	if h.Get("request").IsNull() {
		body = h.Get("body").With(t).Hex()
	} else {
		body = vectors.RulesHandshakeBody(t, h.Get("request").Str())
	}
	a := sc.sessions.ServeHandshake(body, partnerPeer(t, h.Get("peer")))
	if a.Status != 200 {
		return handshakeOutcome(a.Status, string(a.Body), "null", "null")
	}
	r, err := session.ParseReply(a.Body)
	if err != nil {
		t.Fatalf("the reply does not read: %v", err)
	}
	if as := step.Get("as"); !as.IsNull() {
		sc.opened[as.Str()] = r.Sess
	}
	return handshakeOutcome(a.Status, "null", r.Status, fmt.Sprintf("%q", r.Disabled))
}

// expectedHandshake returns a handshake step's expected, in the shape of handshakeOutcome: the body of a
// 400 is exactly {"error":"<code>"}.
func expectedHandshake(e vectors.Node) string {
	body, status, disabled := "null", "null", "null"
	if !e.Get("error").IsNull() {
		body = `{"error":"` + e.Get("error").Str() + `"}`
	}
	if !e.Get("sessionStatus").IsNull() {
		status = e.Get("sessionStatus").Str()
	}
	if !e.Get("disabled").IsNull() {
		disabled = fmt.Sprintf("%q", e.Get("disabled").Strs())
	}
	return handshakeOutcome(int(e.Get("status").Int()), body, status, disabled)
}

func handshakeOutcome(status int, body, sessionStatus, disabled string) string {
	return fmt.Sprintf("{status: %d, body: %s, sessionStatus: %s, disabled: %s}", status, body, sessionStatus, disabled)
}

// call makes a call step's request as the peer it names, its boundary stamp signed now in the session the
// stamp names, and returns its outcome in the shape of expectedCall.
func (sc *partnerScript) call(t *testing.T, c vectors.Node) string {
	t.Helper()
	req := paztporthttp.InboundRequest{
		Method: c.Get("method").Str(),
		Target: c.Get("target").Str(),
		Body:   c.Get("body").With(t).Hex(),
	}
	req.Session = sc.sessionRef(t, c.Get("session"))
	if st := c.Get("stamp"); !st.IsNull() {
		req.Chain = sc.boundaryChain(t, st, req.Method, req.Target)
	}
	if h := c.Get("proofHeader"); !h.IsNull() {
		req.Proof = h.Str()
	}
	if h := c.Get("influenceHeader"); !h.IsNull() {
		req.Influence = h.Str()
	}
	a, err := sc.sessions.Accept(t.Context(), req, partnerPeer(t, c.Get("peer")))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	refusal := a.Refusal
	// As an adapter does: an unsafe session's switched-off operations are refused before the handler runs.
	if refusal == nil && !a.Attested && sc.disabled.Refuses(req.Method, c.Get("routePattern").Str()) {
		r := paztporthttp.UnsafeRefusal()
		refusal = &r
	}
	if refusal != nil {
		if a.Attested || a.Chain != nil || len(a.Influence) != 0 {
			t.Fatalf("a refusal carries what a served call does: %+v", a)
		}
		return callOutcome(fmt.Sprintf("%d %s", refusal.Status, refusal.Body), false, nil, false)
	}
	if a.Attested != (a.Chain != nil) {
		t.Fatalf("Attested is %v with chain %v", a.Attested, a.Chain)
	}
	return callOutcome("null", a.Attested, a.Influence, a.TrustedRecord(nil))
}

// expectedCall returns a call step's expected, in the shape of callOutcome.
func expectedCall(t *testing.T, e vectors.Node) string {
	t.Helper()
	refusal := "null"
	if r := e.Get("refusal"); !r.IsNull() {
		refusal = fmt.Sprintf("%d %s", r.Get("status").Int(), r.Get("body").With(t).Hex())
	}
	return callOutcome(refusal, e.Get("attested").Bool(), entries(e.Get("influence")), e.Get("trustedRecord").Bool())
}

func callOutcome(refusal string, attested bool, infl []influence.Entry, trusted bool) string {
	return fmt.Sprintf("{refusal: %s, attested: %v, influence: %+v, trustedRecord: %v}", refusal, attested, infl,
		trusted)
}

// sessionRef returns the session id ref names: one a handshake opened as {"of": <as>}, a literal
// {"id": <id>}, or "" for null, which sends no X-Path-Session.
func (sc *partnerScript) sessionRef(t *testing.T, ref vectors.Node) string {
	t.Helper()
	switch {
	case ref.IsNull():
		return ""
	case ref.Has("id"):
		return ref.Get("id").Str()
	}
	id, ok := sc.opened[ref.Get("of").Str()]
	if !ok {
		t.Fatalf("no session was opened as %q", ref.Get("of").Str())
	}
	return id
}

// boundaryChain returns the X-Path-Chain value of the one boundary stamp st describes, signed now with
// its key: in the session its sess names, binding the call's method and target and the stamp's own body,
// and committing to the stamp's influence.
func (sc *partnerScript) boundaryChain(t *testing.T, st vectors.Node, method, target string) string {
	t.Helper()
	bind, err := wire.Bind(method, target, st.Get("body").With(t).Hex())
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return signBoundary(t, st, sc.sessionRef(t, st.Get("sess")), bind)
}

// signBoundary returns the X-Path-Chain value of the one boundary stamp st describes, in session sess and
// binding bind, signed now with its key and committing to the stamp's influence.
func signBoundary(t testing.TB, st vectors.Node, sess, bind string) string {
	t.Helper()
	infl, err := influence.Commit(entries(st.Get("influence")))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	key, _ := vectors.RulesKey(t, st.Get("key").Str())
	s, err := stamp.Sign(stamp.Stamp{
		Svc: st.Get("svc").Str(), Inst: st.Get("inst").Str(), RID: st.Get("rid").Str(), TS: st.Get("ts").Int(),
		Sess: sess, Rcv: st.Get("rcv").Str(), Bind: bind, Infl: infl,
	}, key)
	if err != nil {
		t.Fatalf("stamp.Sign: %v", err)
	}
	h, err := wire.EncodeChain(stamp.Chain{s})
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	return h
}

// partnerPeer returns the client certificate the peers name n names, as PeerFromCertificate reads it, or
// nil for null, no client certificate.
func partnerPeer(t testing.TB, n vectors.Node) *paztporthttp.PeerCert {
	t.Helper()
	if n.IsNull() {
		return nil
	}
	der, addr := vectors.RulesPeer(t, n.Str())
	p := paztporthttp.PeerFromCertificate(der, addr)
	return &p
}
