// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// vectorNow is the rules' clock: every material but the expiring ones is current at it.
const vectorNow = 1767225600000

// pspConfig returns the rules' partner psp, pinning shop's policy key and allowing payment as the client's
// origin, with a clock that reads *now, a cap of maxPerPeer and an idle period of idleMs.
func pspConfig(t *testing.T, now *int64, maxPerPeer int, idleMs int64) SessionsConfig {
	t.Helper()
	m := vectors.RulesMaterial(t, "psp")
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
	entryKey, _ := vectors.RulesKey(t, m.Entry)
	return SessionsConfig{
		Root:           root,
		Keyring:        kf,
		PolicyKey:      policyPin(t, m.PolicyKey),
		Entry:          m.Entry,
		EntryKey:       entryKey,
		ReplyCert:      cert,
		Pinned:         []string{policyPin(t, "shop-policy")},
		ClientOrigins:  []string{"payment"},
		UnsafeDisabled: []string{"POST /refund"},
		MaxPerPeer:     maxPerPeer,
		IdleMs:         idleMs,
		CallMaxAgeMs:   5000,
		RunMaxAgeMs:    5000,
		Nonces:         verify.NewMemoryNonceCache(15000),
		Now:            func() int64 { return *now },
	}
}

func policyPin(t *testing.T, name string) string {
	t.Helper()
	_, pub := vectors.RulesKey(t, name)
	return keys.EncodePublic(pub)
}

func newSessions(t *testing.T, cfg SessionsConfig) *Sessions {
	t.Helper()
	s, err := NewSessions(cfg)
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	return s
}

// rulesPeer returns the rules' client certificate called name, as a receiver reads it.
func rulesPeer(t *testing.T, name string) *PeerCert {
	t.Helper()
	der, addr := vectors.RulesPeer(t, name)
	p := PeerFromCertificate(der, addr)
	return &p
}

// opened returns the reply a 200 answer holds, failing t for any other answer.
func opened(t *testing.T, a Answer) session.Reply {
	t.Helper()
	if a.Status != 200 {
		t.Fatalf("the handshake is answered %d %s", a.Status, a.Body)
	}
	r, err := session.ParseReply(a.Body)
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	return r
}

// registry is what the sessions hold, read under their lock: each id's peer and when a call last used it,
// and each peer's ids, least recently used first.
type registry struct {
	byID   map[string]string
	byPeer map[string][]string
}

func snapshot(s *Sessions) registry {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := registry{byID: map[string]string{}, byPeer: map[string][]string{}}
	for id, e := range s.byID {
		r.byID[id] = e.peer.issuer + "|" + e.peer.svc + "|" + strconv.FormatInt(e.lastUsed, 10)
	}
	for p, es := range s.byPeer {
		for _, e := range es {
			r.byPeer[p.issuer+"|"+p.svc] = append(r.byPeer[p.issuer+"|"+p.svc], e.id)
		}
	}
	return r
}

func (r registry) equal(o registry) bool {
	return maps.Equal(r.byID, o.byID) && maps.EqualFunc(r.byPeer, o.byPeer, slices.Equal[[]string])
}

func TestNewSessionsRefusesAnUnusableConfig(t *testing.T) {
	now := int64(vectorNow)
	good := pspConfig(t, &now, 2, 60000)
	if _, err := NewSessions(good); err != nil {
		t.Fatalf("NewSessions(good) = %v", err)
	}
	shop := vectors.RulesMaterial(t, "shop")
	shopKeyring, err := policy.ParseKeyringFile(shop.Keyring)
	if err != nil {
		t.Fatalf("ParseKeyringFile: %v", err)
	}
	for _, tc := range []struct {
		name  string
		field string
		edit  func(*SessionsConfig)
	}{
		{"no pinned key", "Pinned", func(c *SessionsConfig) { c.Pinned = nil }},
		{"no client origin", "ClientOrigins", func(c *SessionsConfig) { c.ClientOrigins = []string{} }},
		{"a cap of 0", "MaxPerPeer", func(c *SessionsConfig) { c.MaxPerPeer = 0 }},
		{"a negative cap", "MaxPerPeer", func(c *SessionsConfig) { c.MaxPerPeer = -1 }},
		{"an idle period of 0", "IdleMs", func(c *SessionsConfig) { c.IdleMs = 0 }},
		{"a negative idle period", "IdleMs", func(c *SessionsConfig) { c.IdleMs = math.MinInt64 }},
		{"no nonce cache", "Nonces", func(c *SessionsConfig) { c.Nonces = nil }},
		{"no clock", "Now", func(c *SessionsConfig) { c.Now = nil }},
		{"another organisation's keyring", "Keyring", func(c *SessionsConfig) { c.Keyring = shopKeyring }},
		{"a keyring under another policy key", "Keyring", func(c *SessionsConfig) { c.PolicyKey = policyPin(t, "shop-policy") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.edit(&cfg)
			s, err := NewSessions(cfg)
			if err == nil {
				t.Fatalf("NewSessions = %v, nil; want an error", s)
			}
			if s != nil {
				t.Errorf("NewSessions returns sessions with its error")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the error %q does not name %s", err, tc.field)
			}
			if strings.Contains(err.Error(), "MCow") {
				t.Errorf("the error %q echoes a key", err)
			}
		})
	}
}

// TestSessionsKeepTheirOwnCopy: the sessions keep the configuration they were given, whatever the caller
// does to its slices and maps afterwards.
func TestSessionsKeepTheirOwnCopy(t *testing.T) {
	now := int64(vectorNow)
	cfg := pspConfig(t, &now, 2, 60000)
	cfg.Keyring.Services = maps.Clone(cfg.Keyring.Services)
	s := newSessions(t, cfg)
	cfg.Pinned[0] = policyPin(t, "stranger-policy")
	cfg.UnsafeDisabled[0] = "GET /changed"
	cfg.ClientOrigins[0] = "orders"
	clear(cfg.EntryKey)
	clear(cfg.Keyring.Services)
	shop := vectors.RulesHandshakeBody(t, "shop")
	req, err := session.ParseRequest(shop)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	a := ServeHandshake(shop, rulesPeer(t, "shop"), s)
	r := opened(t, a)
	if r.Status != session.StatusAttested || len(r.ServerKeyring) == 0 {
		t.Fatalf("the reply is %s with keyring %v after the caller changed its config", r.Status, r.ServerKeyring)
	}
	if got := session.CheckReply(a.Body, req, cfg.PolicyKey, "psp", now); got != session.Attested {
		t.Fatalf("CheckReply = %s after the caller changed its entry key, want %s", got, session.Attested)
	}
	// payment is still the session's origin: its call passes every check up to the route, and has no proof.
	pa, err := s.Accept(t.Context(), boundaryCall(t, r.Sess, now), rulesPeer(t, "shop"))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if pa.Result == nil || pa.Result.Reason != reason.PathNotAllowed {
		t.Fatalf("a call from payment is %+v after the caller changed its origins; want PATH_NOT_ALLOWED", pa)
	}
	u := opened(t, ServeHandshake(vectors.RulesHandshakeBody(t, "no-root"), rulesPeer(t, "shop"), s))
	if len(u.Disabled) != 1 || u.Disabled[0] != "POST /refund" {
		t.Fatalf("the unsafe reply disables %q", u.Disabled)
	}
}

// TestSessionsHoldTheCapUnderConcurrentHandshakes: 64 handshakes at once from one peer never leave it
// more than its cap of live sessions, as read under the lock after each one and by a watcher that reads
// it under the lock throughout, and leave it exactly its cap.
func TestSessionsHoldTheCapUnderConcurrentHandshakes(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 2, 60000))
	body := vectors.RulesHandshakeBody(t, "shop")
	peer := rulesPeer(t, "shop")
	key := peerKey{issuer: peer.Issuer, svc: peer.Peer.Svc}
	done := make(chan struct{})
	watched := make(chan int)
	go func() {
		most := 0
		for {
			s.mu.Lock()
			most = max(most, len(s.byPeer[key]), len(s.byID))
			s.mu.Unlock()
			select {
			case <-done:
				watched <- most
				return
			default:
			}
		}
	}()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	for range 64 {
		wg.Go(func() {
			a := ServeHandshake(body, peer, s)
			if a.Status != 200 {
				t.Errorf("a handshake is answered %d %s", a.Status, a.Body)
				return
			}
			s.mu.Lock()
			live, total := len(s.byPeer[key]), len(s.byID)
			s.mu.Unlock()
			if live > 2 || total > 2 {
				t.Errorf("the peer holds %d live sessions of %d, over its cap of 2", live, total)
			}
			r, err := session.ParseReply(a.Body)
			if err != nil {
				t.Errorf("ParseReply: %v", err)
				return
			}
			mu.Lock()
			ids[r.Sess] = true
			mu.Unlock()
		})
	}
	wg.Wait()
	close(done)
	if most := <-watched; most > 2 {
		t.Errorf("the watcher saw %d live sessions, over the cap of 2", most)
	}
	if len(ids) != 64 {
		t.Errorf("64 handshakes opened %d distinct sessions", len(ids))
	}
	got := snapshot(s)
	if len(got.byID) != 2 || len(got.byPeer) != 1 || len(got.byPeer[peer.Issuer+"|"+peer.Peer.Svc]) != 2 {
		t.Fatalf("after 64 handshakes the sessions hold %v", got)
	}
}

// requestOfLength returns the canonical bytes of shop's handshake request with a service added to its
// keyring, so that they are exactly n bytes long, n at most one past the wire limit. The writer refuses
// bytes over the limit, so the last is added by hand. The keyring's signature no longer covers the
// keyring, so a request that reads opens an unsafe session.
func requestOfLength(t *testing.T, n int) []byte {
	t.Helper()
	const limit = 262144
	if n > limit+1 {
		t.Fatalf("requestOfLength(%d) is more than one past the limit", n)
	}
	req, err := session.ParseRequest(vectors.RulesHandshakeBody(t, "shop"))
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	req.ClientKeyring = maps.Clone(req.ClientKeyring)
	req.ClientKeyring["zz"] = ""
	b, err := req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	req.ClientKeyring["zz"] = strings.Repeat("A", min(n, limit)-len(b))
	if b, err = req.Wire(); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if n > limit {
		pad := []byte(`"zz":"`)
		i := bytes.Index(b, pad) + len(pad)
		b = slices.Concat(b[:i], []byte("A"), b[i:])
	}
	if len(b) != n {
		t.Fatalf("the padded request is %d bytes, want %d", len(b), n)
	}
	return b
}

// TestServeHandshakeWireLimit: a body of 262 144 bytes is read, and opens a session; one of 262 145, a
// request's canonical bytes but for its length, is INVALID_PARAMS. With no peer, the body is not read at
// all: one that is no request is NO_SESSION, never INVALID_PARAMS.
func TestServeHandshakeWireLimit(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 16, 60000))
	peer := rulesPeer(t, "shop")

	if a := ServeHandshake([]byte("not a request"), nil, s); a.Status != 400 || string(a.Body) != `{"error":"NO_SESSION"}` {
		t.Fatalf("no peer: %d %s; want 400 NO_SESSION", a.Status, a.Body)
	}
	over := ServeHandshake(requestOfLength(t, 262145), peer, s)
	if over.Status != 400 || string(over.Body) != `{"error":"INVALID_PARAMS"}` {
		t.Fatalf("262 145 bytes: %d %s; want 400 INVALID_PARAMS", over.Status, over.Body)
	}
	if at := opened(t, ServeHandshake(requestOfLength(t, 262144), peer, s)); at.Status != session.StatusUnsafe {
		t.Fatalf("262 144 bytes: %s; want an unsafe session", at.Status)
	}
}

// TestHandshakeReplyIsSignedByTheEntryKey: the reply is in the entry-key form and passes the client's
// check against the partner's pinned policy key and its entry service.
func TestHandshakeReplyIsSignedByTheEntryKey(t *testing.T) {
	now := int64(vectorNow)
	cfg := pspConfig(t, &now, 16, 60000)
	s := newSessions(t, cfg)
	body := vectors.RulesHandshakeBody(t, "shop")
	req, err := session.ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	a := ServeHandshake(body, rulesPeer(t, "shop"), s)
	r := opened(t, a)
	if r.ServerReplyCert == nil || r.ServerKeyringSig == nil || r.ServerKeyringNotAfter == nil {
		t.Fatalf("the reply is not in the entry-key form: %+v", r)
	}
	if got := session.CheckReply(a.Body, req, cfg.PolicyKey, "psp", now); got != session.Attested {
		t.Fatalf("CheckReply = %s, want %s", got, session.Attested)
	}
	if len(r.Disabled) != 0 {
		t.Fatalf("an attested session disables %q", r.Disabled)
	}
}

// TestHandshakeFromAnUnpinnedClientIsUnsafe: a client whose policy key the partner has not pinned opens
// an unsafe session, however well its material verifies under its own key.
func TestHandshakeFromAnUnpinnedClientIsUnsafe(t *testing.T) {
	now := int64(vectorNow)
	cfg := pspConfig(t, &now, 16, 60000)
	cfg.Pinned = []string{policyPin(t, "stranger-policy")}
	s := newSessions(t, cfg)
	r := opened(t, ServeHandshake(vectors.RulesHandshakeBody(t, "shop"), rulesPeer(t, "shop"), s))
	if r.Status != session.StatusUnsafe {
		t.Fatalf("an unpinned client's session is %s, want unsafe", r.Status)
	}
}

// TestHandshakeWithMaterialPinnedRefusesOpensAnUnsafeSession: a client keyring that Status attests but
// verify.Pinned refuses, here one holding a key that is not an Ed25519 key, opens an unsafe session with
// the disabled list, never an error, and its calls are served unsafe.
func TestHandshakeWithMaterialPinnedRefusesOpensAnUnsafeSession(t *testing.T) {
	now := int64(vectorNow)
	cfg := pspConfig(t, &now, 16, 60000)
	s := newSessions(t, cfg)
	shop := vectors.RulesMaterial(t, "shop")
	root, err := policy.ParseRootFile(shop.Root)
	if err != nil {
		t.Fatalf("ParseRootFile: %v", err)
	}
	policyKey, _ := vectors.RulesKey(t, "shop-policy")
	pin := policyPin(t, "shop-policy")
	kf, err := policy.SignKeyring(map[string]string{"payment": "not-a-key"}, pin, root.NotAfter, policyKey)
	if err != nil {
		t.Fatalf("SignKeyring: %v", err)
	}
	req := session.NewRequest(&root, pin, kf, session.NewNonce())
	if got := session.Status(req, &cfg.Root, cfg.Keyring, cfg.PolicyKey, cfg.Pinned, now); got != session.StatusAttested {
		t.Fatalf("Status = %s; the case needs material Status attests", got)
	}
	body, err := req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	a := ServeHandshake(body, rulesPeer(t, "shop"), s)
	r := opened(t, a)
	if r.Status != session.StatusUnsafe || len(r.Disabled) != 1 || r.Disabled[0] != "POST /refund" {
		t.Fatalf("the reply is %s disabling %q; want unsafe disabling POST /refund", r.Status, r.Disabled)
	}
	if got := session.CheckReply(a.Body, req, cfg.PolicyKey, "psp", now); got != session.Unsafe {
		t.Fatalf("CheckReply = %s, want %s", got, session.Unsafe)
	}
	pa, err := s.Accept(t.Context(), InboundRequest{Method: "POST", Target: "/charge", Session: r.Sess}, rulesPeer(t, "shop"))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if pa.Refusal != nil || pa.Attested || pa.Result != nil {
		t.Fatalf("a call in the unsafe session is %+v; want served unsafe, unverified", pa)
	}
}

// TestFailedHandshakesChangeNoSession: a handshake that opens no session leaves every session as it was,
// an expired one included.
func TestFailedHandshakesChangeNoSession(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 1, 60000))
	shop := vectors.RulesHandshakeBody(t, "shop")
	peer := rulesPeer(t, "shop")
	opened(t, ServeHandshake(shop, peer, s))
	now += 60000 // the session has expired, but is still held
	before := snapshot(s)
	if len(before.byID) != 1 {
		t.Fatalf("the sessions hold %v", before)
	}
	noIssuer := *peer
	noIssuer.Issuer = ""
	noName := *peer
	noName.Peer.Svc = ""
	for _, tc := range []struct {
		name string
		body []byte
		peer *PeerCert
		code string
	}{
		{"no peer", shop, nil, "NO_SESSION"},
		{"no issuer", shop, &noIssuer, "NO_SESSION"},
		{"no service", shop, &noName, "NO_SESSION"},
		{"over the limit", requestOfLength(t, 262145), peer, "INVALID_PARAMS"},
		{"not a request", []byte("[]"), peer, "INVALID_PARAMS"},
		{"a short nonce", vectors.RulesHandshakeBody(t, "short-nonce"), peer, "NO_SESSION"},
		{"a short root signature", vectors.RulesHandshakeBody(t, "short-root-sig"), peer, "NO_SESSION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ServeHandshake(tc.body, tc.peer, s)
			if a.Status != 400 || string(a.Body) != `{"error":"`+tc.code+`"}` {
				t.Fatalf("answered %d %s, want 400 %s", a.Status, a.Body, tc.code)
			}
			if after := snapshot(s); !after.equal(before) {
				t.Fatalf("the sessions changed from %v to %v", before, after)
			}
		})
	}
}

// TestHandshakesSweepEveryPeersExpiredSessions: a handshake that opens a session first drops every expired
// session, another peer's included, and counts the cap per peer: another peer's sessions never count
// against it.
func TestHandshakesSweepEveryPeersExpiredSessions(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 2, 60000))
	body := vectors.RulesHandshakeBody(t, "shop")
	shop, clinic := rulesPeer(t, "shop"), rulesPeer(t, "clinic")
	shopKey := shop.Issuer + "|" + shop.Peer.Svc
	clinicKey := clinic.Issuer + "|" + clinic.Peer.Svc
	if shopKey == clinicKey {
		t.Fatal("the case needs two peers")
	}
	opened(t, ServeHandshake(body, shop, s))
	now += 60000 // shop's session has expired
	c1 := opened(t, ServeHandshake(body, clinic, s)).Sess
	c2 := opened(t, ServeHandshake(body, clinic, s)).Sess
	got := snapshot(s)
	if want := map[string][]string{clinicKey: {c1, c2}}; !maps.EqualFunc(got.byPeer, want, slices.Equal[[]string]) ||
		len(got.byID) != 2 {
		t.Fatalf("after clinic's handshakes the sessions hold %v; want only clinic's %v", got, want)
	}
	s1 := opened(t, ServeHandshake(body, shop, s)).Sess
	got = snapshot(s)
	if want := map[string][]string{clinicKey: {c1, c2}, shopKey: {s1}}; !maps.EqualFunc(got.byPeer, want, slices.Equal[[]string]) ||
		len(got.byID) != 3 {
		t.Fatalf("after shop's handshake the sessions hold %v; want %v", got, want)
	}
}

// TestAddRefusesAnIdInUse: a session whose id is already in use, which would take a repeated server
// nonce, is refused, and every session is left as it was, an expired one included.
func TestAddRefusesAnIdInUse(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 16, 60000))
	shop := peerKey{issuer: "CN=shop CA", svc: "payment"}
	if !s.add(&sessionEntry{id: "a", peer: shop}) {
		t.Fatal("add refuses a new id")
	}
	now += 1000
	if !s.add(&sessionEntry{id: "b", peer: shop}) {
		t.Fatal("add refuses a new id")
	}
	now += 59500 // a has expired, b has not
	before := snapshot(s)
	if s.add(&sessionEntry{id: "b", peer: peerKey{issuer: "CN=other CA", svc: "payment"}}) {
		t.Fatal("add takes an id already in use")
	}
	if after := snapshot(s); !after.equal(before) {
		t.Fatalf("the sessions changed from %v to %v", before, after)
	}
}

// TestSessionsMatchNoPeerWithoutAnIssuerOrAName: a call whose certificate has no issuer, or names no
// service, matches no session, even under the other half of the peer that opened it.
func TestSessionsMatchNoPeerWithoutAnIssuerOrAName(t *testing.T) {
	now := int64(vectorNow)
	s := newSessions(t, pspConfig(t, &now, 16, 60000))
	peer := rulesPeer(t, "shop")
	id := opened(t, ServeHandshake(vectors.RulesHandshakeBody(t, "shop"), peer, s)).Sess
	noIssuer := *peer
	noIssuer.Issuer = ""
	noName := *peer
	noName.Peer.Svc = ""
	for _, p := range []*PeerCert{&noIssuer, &noName, nil} {
		a, err := s.Accept(t.Context(), InboundRequest{Method: "POST", Target: "/charge", Session: id}, p)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if a.Refusal == nil || a.Refusal.Status != 403 || string(a.Refusal.Body) != `{"reason":"SESSION_UNKNOWN"}` {
			t.Fatalf("the call as %+v is %+v; want 403 SESSION_UNKNOWN", p, a)
		}
	}
	// A blank header is no header: the call is served unsafe.
	a, err := s.Accept(t.Context(), InboundRequest{Method: "POST", Target: "/charge", Session: " \t"}, peer)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if a.Refusal != nil || a.Attested || a.Result != nil {
		t.Fatalf("a call with a blank session header is %+v; want served unsafe", a)
	}
	// The session is still the opener's.
	a, err = s.Accept(t.Context(), InboundRequest{Method: "POST", Target: "/charge", Session: " " + id + "\t"}, peer)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if a.Refusal == nil || string(a.Refusal.Body) != `{"reason":"CHAIN_MISSING"}` || a.Result == nil ||
		a.Result.Reason != reason.ChainMissing {
		t.Fatalf("a call with no chain in the opener's session is %+v; want 403 CHAIN_MISSING with its result", a)
	}
	// The verifier was given the certificate's peer, whom its result then names.
	if a.Result.SuspectSvc != peer.Peer.Svc || a.Result.SuspectInst != peer.Peer.Inst {
		t.Fatalf("the result names %s@%s, want the peer %s@%s", a.Result.SuspectSvc, a.Result.SuspectInst,
			peer.Peer.Svc, peer.Peer.Inst)
	}
}

// boundaryCall returns a POST /charge in session id, with one boundary stamp signed at ts by payment for
// psp, binding the call and committing to no influence, and no proof.
func boundaryCall(t *testing.T, id string, ts int64) InboundRequest {
	t.Helper()
	body := []byte("{}")
	bind, err := wire.Bind("POST", "/charge", body)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	key, _ := vectors.RulesKey(t, "payment")
	st, err := stamp.Sign(stamp.Stamp{
		Svc: "payment", Inst: "pay-1", RID: "rid-1", TS: ts, Sess: id, Rcv: "psp", Bind: bind,
	}, key)
	if err != nil {
		t.Fatalf("stamp.Sign: %v", err)
	}
	chain, err := wire.EncodeChain(stamp.Chain{st})
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	return InboundRequest{Method: "POST", Target: "/charge", Chain: chain, Session: id, Body: body}
}

// failingCache is a nonce cache whose store is down.
type failingCache struct{}

var errStoreDown = errors.New("the store is down")

func (failingCache) SeenBefore(context.Context, string, int64) (bool, error) {
	return false, errStoreDown
}
func (failingCache) TTL() int64 { return 15000 }

// TestAcceptReturnsTheNonceCacheError: a nonce cache that cannot answer is Accept's error, with the zero
// PartnerAccepted, never a verdict.
func TestAcceptReturnsTheNonceCacheError(t *testing.T) {
	now := int64(vectorNow)
	cfg := pspConfig(t, &now, 16, 60000)
	cfg.Nonces = failingCache{}
	s := newSessions(t, cfg)
	peer := rulesPeer(t, "shop")
	id := opened(t, ServeHandshake(vectors.RulesHandshakeBody(t, "shop"), peer, s)).Sess
	a, err := s.Accept(t.Context(), boundaryCall(t, id, now), peer)
	if !errors.Is(err, errStoreDown) {
		t.Fatalf("Accept = %v, want the cache's error", err)
	}
	if a.Refusal != nil || a.Attested || a.Chain != nil || a.Influence != nil || a.Result != nil {
		t.Fatalf("Accept returns %+v with its error, want the zero PartnerAccepted", a)
	}
}

// TestIdleExpiryIsExact: a session expires once now - lastUsed >= idle, computed exactly: a difference
// too large for an int64 is past every idle period, and one too small is within each.
func TestIdleExpiryIsExact(t *testing.T) {
	for _, tc := range []struct {
		now, last, idle int64
		want            bool
	}{
		{1000, 0, 1000, true},
		{999, 0, 1000, false},
		{0, 1000, 1, false},
		{math.MaxInt64, math.MinInt64, math.MaxInt64, true},
		{math.MinInt64, math.MaxInt64, 1, false},
		{math.MaxInt64, -1, math.MaxInt64, true},
		{math.MinInt64, 1, 1, false},
	} {
		if got := idleExpired(tc.now, tc.last, tc.idle); got != tc.want {
			t.Errorf("idleExpired(%d, %d, %d) = %v, want %v", tc.now, tc.last, tc.idle, got, tc.want)
		}
	}
}
