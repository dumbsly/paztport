// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// now is the fixture's clock.
const now int64 = 1767225600000

// setup is one request to a verifier: the stamps to sign into its chain, edits made to them before and
// after signing, the verifier's Config and the rest of the Input. The fixture is the mesh policy of
// v3.json: gateway, then orders, calling payment.
type setup struct {
	t      *testing.T
	stamps []stamp.Stamp                 // nil for no chain
	pre    []func(i int, s *stamp.Stamp) // before signing, once prev links to the stamp before
	post   []func(i int, s *stamp.Stamp) // after signing
	wire   func([]byte) []byte           // on the chain's wire bytes, if set
	cfg    verify.Config
	in     verify.Input
}

func ptr(s string) *string { return &s }

// mesh returns the fixture's setup, which verifies OK.
func mesh(t *testing.T) *setup {
	t.Helper()
	p := vectors.Load(t, "v3.json").Get("policies").Get("mesh")
	root, err := b64.Decode(p.Get("root").Str())
	if err != nil {
		t.Fatal(err)
	}
	return &setup{
		t: t,
		stamps: []stamp.Stamp{
			{Svc: "gateway", Inst: "gw-1", RID: "rid-1", TS: now - 1500, Rcv: "orders", Bind: "bind-0"},
			{Svc: "orders", Inst: "ord-1", RID: "rid-1", TS: now - 500, Rcv: "payment", Bind: "bind-1"},
		},
		cfg: verify.Config{
			Keyring:        policy.Keyring{"gateway": pub(t, "gateway"), "orders": pub(t, "orders"), "pi": pub(t, "pi")},
			Root:           root,
			RootID:         p.Get("rootId").Str(),
			PolicyNotAfter: 4102444800000,
			AllowedOrigins: []string{"gateway"},
			Nonces:         verify.NewMemoryNonceCache(verify.NonceTTLMs),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   verify.CallMaxAgeMs,
			RunMaxAgeMs:    verify.RunMaxAgeMs,
		},
		in: verify.Input{
			ExpectedBind:    ptr("bind-1"),
			Proof:           ptr(p.Get("proofTokens").Get("gateway/orders/payment").Str()),
			Receiver:        "payment",
			ReceiverInRoute: true,
			NonceKey:        ptr("rid-1|orders|req"),
		},
	}
}

func pub(t *testing.T, name string) ed25519.PublicKey {
	_, pub := vectors.V3Key(t, name)
	return pub
}

// edit changes stamp i before it is signed.
func (s *setup) edit(i int, f func(*stamp.Stamp)) {
	s.pre = append(s.pre, func(j int, st *stamp.Stamp) {
		if j == i {
			f(st)
		}
	})
}

// tamper changes stamp i after it is signed.
func (s *setup) tamper(i int, f func(*stamp.Stamp)) {
	s.post = append(s.post, func(j int, st *stamp.Stamp) {
		if j == i {
			f(st)
		}
	})
}

// token signs the setup's stamps, each with its own service's key (pi's for a service with none), and
// returns the chain's token.
func (s *setup) token(t *testing.T) string {
	t.Helper()
	c := make(stamp.Chain, len(s.stamps))
	for i, st := range s.stamps {
		if i > 0 {
			st.Prev = c[i-1].Sig
		}
		for _, f := range s.pre {
			f(i, &st)
		}
		name := st.Svc
		if !slices.Contains([]string{"gateway", "orders", "pi", "session"}, name) {
			name = "pi"
		}
		priv, _ := vectors.V3Key(t, name)
		signed, err := stamp.Sign(st, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		for _, f := range s.post {
			f(i, &signed)
		}
		c[i] = signed
	}
	b, err := c.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if s.wire != nil {
		b = s.wire(b)
	}
	return b64.Encode(b)
}

// run verifies the setup's request once.
func (s *setup) run(t *testing.T) verify.Result {
	t.Helper()
	in := s.in
	if s.stamps != nil {
		in.Chain = ptr(s.token(t))
	}
	r, err := verify.New(s.cfg).Verify(t.Context(), in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return r
}

// named returns the result the spec names for code: no one for POLICY_EXPIRED; with a peer, the peer;
// without one, the last stamp for OK and PATH_NOT_ALLOWED and no one otherwise.
func (s *setup) named(code reason.Code) verify.Result {
	r := verify.Result{Reason: code}
	switch {
	case code == reason.PolicyExpired:
	case s.in.Peer != nil:
		r.SuspectSvc, r.SuspectInst = s.in.Peer.Svc, s.in.Peer.Inst
	case code == reason.OK || code == reason.PathNotAllowed:
		r.SuspectSvc, r.SuspectInst = "orders", "ord-1"
	}
	return r
}

// A fault breaks one check of the live order.
type fault struct {
	name string
	code reason.Code
	make func(*setup)
}

// faults are one or more for each check of the live order, in its order.
var faults = []fault{
	{"policy expired", reason.PolicyExpired, func(s *setup) { s.cfg.PolicyNotAfter = now - 1 }},
	{"policy window below 0", reason.PolicyExpired, func(s *setup) {
		s.cfg.PolicyNotAfter = -1
		s.cfg.Now = func() int64 { return -2 }
	}},
	{"policy window past 2^53 - 1", reason.PolicyExpired, func(s *setup) { s.cfg.PolicyNotAfter = 1 << 53 }},
	{"no chain", reason.ChainMissing, func(s *setup) { s.stamps = nil }},
	{"an empty chain token", reason.ChainMissing, func(s *setup) {
		s.stamps = nil
		s.in.Chain = ptr("")
	}},
	{"a delimiter in rcv", reason.BadSignature, func(s *setup) {
		s.wire = func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"rcv":"payment"`), []byte(`"rcv":"pay|ment"`), 1)
		}
	}},
	{"an origin not allowed", reason.BadOrigin, func(s *setup) { s.cfg.AllowedOrigins = []string{"orders"} }},
	{"no origins allowed", reason.BadOrigin, func(s *setup) { s.cfg.AllowedOrigins = nil }},
	{"a bad signature", reason.BadSignature, func(s *setup) { s.tamper(1, func(st *stamp.Stamp) { st.Inst = "ord-2" }) }},
	{"a bad origin signature", reason.BadSignature, func(s *setup) { s.tamper(0, func(st *stamp.Stamp) { st.TS++ }) }},
	{"a sig of 63 bytes", reason.BadSignature, func(s *setup) {
		s.tamper(1, func(st *stamp.Stamp) { st.Sig = b64.Encode(make([]byte, 63)) })
	}},
	{"no key for a signer", reason.BadSignature, func(s *setup) { delete(s.cfg.Keyring, "orders") }},
	{"another service's key", reason.BadSignature, func(s *setup) { s.cfg.Keyring["orders"] = pub(s.t, "pi") }},
	{"a broken link", reason.BrokenLink, func(s *setup) { s.edit(1, func(st *stamp.Stamp) { st.Prev = "AAAA" }) }},
	{"an origin with a prev", reason.BrokenLink, func(s *setup) { s.edit(0, func(st *stamp.Stamp) { st.Prev = "AAAA" }) }},
	{"an inner rcv for another hop", reason.BindingMismatch, func(s *setup) {
		s.edit(0, func(st *stamp.Stamp) { st.Rcv = "payment" })
	}},
	{"a chain for another receiver", reason.BindingMismatch, func(s *setup) { s.in.Receiver = "billing" }},
	{"another rid", reason.RIDMismatch, func(s *setup) { s.edit(1, func(st *stamp.Stamp) { st.RID = "rid-2" }) }},
	{"another rid at the origin", reason.RIDMismatch, func(s *setup) {
		s.edit(0, func(st *stamp.Stamp) { st.RID = "rid-2" })
	}},
	{"another session", reason.SessionUnknown, func(s *setup) { s.cfg.Sess = "sess-1" }},
	{"a stamp in another session", reason.SessionUnknown, func(s *setup) {
		s.edit(0, func(st *stamp.Stamp) { st.Sess = "sess-1" })
	}},
	{"a stale call", reason.Expired, func(s *setup) { s.cfg.Now = func() int64 { return now + verify.CallMaxAgeMs } }},
	{"another binding", reason.BindingMismatch, func(s *setup) { s.in.ExpectedBind = ptr("bind-0") }},
	{"no expected binding", reason.BindingMismatch, func(s *setup) { s.in.ExpectedBind = nil }},
	{"an empty influence token", reason.InfluenceMismatch, func(s *setup) { s.in.Influence = ptr("") }},
	{"influence the stamp does not commit to", reason.InfluenceMismatch, func(s *setup) {
		s.in.Influence = ptr(entriesToken(s.t, entries))
	}},
	{"no nonce key", reason.Replay, func(s *setup) { s.in.NonceKey = nil }},
	{"a cache that forgets too soon", reason.Replay, func(s *setup) {
		s.cfg.Nonces = verify.NewMemoryNonceCache(2*verify.CallMaxAgeMs - 1)
	}},
	{"a key already spent", reason.Replay, func(s *setup) {
		c := verify.NewMemoryNonceCache(verify.NonceTTLMs)
		if _, err := c.SeenBefore(s.t.Context(), "rid-1|orders|req", now); err != nil {
			s.t.Fatal(err)
		}
		s.cfg.Nonces = c
	}},
	{"no proof", reason.PathNotAllowed, func(s *setup) { s.in.Proof = nil }},
	{"a route the proof does not prove", reason.PathNotAllowed, func(s *setup) { s.in.ReceiverInRoute = false }},
	{"a proof for another tree", reason.PathNotAllowed, func(s *setup) { s.cfg.RootID = "v0" }},
	{"another peer", reason.PeerMismatch, func(s *setup) { s.in.Peer = &verify.Peer{Svc: "search", Inst: "10.0.0.9"} }},
	{"a peer with no svc", reason.PeerMismatch, func(s *setup) { s.in.Peer = &verify.Peer{} }},
}

// TestOK pins the fixture: it verifies, and names its last signer.
func TestOK(t *testing.T) {
	s := mesh(t)
	if got, want := s.run(t), s.named(reason.OK); got != want {
		t.Fatalf("Verify = %+v, want %+v", got, want)
	}
}

// TestEachCheck breaks each check alone, and expects its code and the spec's naming: without a peer, only
// OK and PATH_NOT_ALLOWED name the last stamp; with one, every result but POLICY_EXPIRED names the peer.
func TestEachCheck(t *testing.T) {
	peers := map[string]*verify.Peer{"no peer": nil, "a peer": {Svc: "orders", Inst: "10.0.0.7"}}
	for name, peer := range peers {
		t.Run(name, func(t *testing.T) {
			for _, f := range faults {
				t.Run(f.name, func(t *testing.T) {
					s := mesh(t)
					s.in.Peer = peer
					f.make(s)
					if got, want := s.run(t), s.named(f.code); got != want {
						t.Fatalf("Verify = %+v, want %+v", got, want)
					}
				})
			}
		})
	}
}

// TestOrder breaks two adjacent checks of the live order at once, for each pair, and expects the first.
func TestOrder(t *testing.T) {
	byName := map[string]fault{}
	for _, f := range faults {
		byName[f.name] = f
	}
	pairs := [][2]string{
		{"policy expired", "no chain"},
		{"policy expired", "a bad signature"},
		{"a delimiter in rcv", "an origin not allowed"},
		{"an origin not allowed", "a bad signature"},
		{"a bad signature", "an inner rcv for another hop"},
		{"a broken link", "an inner rcv for another hop"},
		{"a broken link", "a chain for another receiver"},
		{"an inner rcv for another hop", "another rid"},
		{"another rid", "another session"},
		{"another session", "a stale call"},
		{"a stale call", "another binding"},
		{"another binding", "an empty influence token"},
		{"an empty influence token", "no nonce key"},
		{"an empty influence token", "a cache that forgets too soon"},
		{"no nonce key", "no proof"},
		{"a key already spent", "no proof"},
		{"no proof", "another peer"},
	}
	for _, p := range pairs {
		first, second := byName[p[0]], byName[p[1]]
		if first.make == nil || second.make == nil {
			t.Fatalf("no fault named %q or %q", p[0], p[1])
		}
		t.Run(p[0]+", then "+p[1], func(t *testing.T) {
			s := mesh(t)
			second.make(s)
			first.make(s)
			if got, want := s.run(t), s.named(first.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestSignatureThenLink pins check 4's loop: each stamp's signature, then its link, before the next stamp.
func TestSignatureThenLink(t *testing.T) {
	third := stamp.Stamp{Svc: "pi", Inst: "pi-1", RID: "rid-1", TS: now - 100, Rcv: "payment", Bind: "bind-2"}
	tests := []struct {
		name string
		code reason.Code
		make func(*setup)
	}{
		{"a broken link before a bad signature", reason.BrokenLink, func(s *setup) {
			s.edit(1, func(st *stamp.Stamp) { st.Prev = "AAAA" })
			s.tamper(2, func(st *stamp.Stamp) { st.Inst = "pi-2" })
		}},
		{"a bad signature before a broken link", reason.BadSignature, func(s *setup) {
			s.tamper(1, func(st *stamp.Stamp) { st.Inst = "ord-2" })
			s.edit(2, func(st *stamp.Stamp) { st.Prev = "AAAA" })
		}},
		{"a bad signature and a broken link on one stamp", reason.BadSignature, func(s *setup) {
			s.edit(1, func(st *stamp.Stamp) { st.Prev = "AAAA" })
			s.tamper(1, func(st *stamp.Stamp) { st.Inst = "ord-2" })
		}},
		{"a bad signature after a wrong inner rcv", reason.BadSignature, func(s *setup) {
			s.edit(0, func(st *stamp.Stamp) { st.Rcv = "pi" })
			s.tamper(2, func(st *stamp.Stamp) { st.Inst = "pi-2" })
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.stamps[1].Rcv = "pi"
			s.stamps = append(s.stamps, third)
			s.in.ExpectedBind = ptr("bind-2")
			tt.make(s)
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestFreshness pins check 7's four bounds, each inclusive.
func TestFreshness(t *testing.T) {
	const call, run = verify.CallMaxAgeMs, verify.RunMaxAgeMs
	tests := []struct {
		name         string
		origin, last int64 // the stamps' ts, as offsets from now
		code         reason.Code
	}{
		{"the last stamp a call window old", -call, -call, reason.OK},
		{"the last stamp past the call window", -call - 1, -call - 1, reason.Expired},
		{"the last stamp a call window ahead", call, call, reason.OK},
		{"the last stamp past a call window ahead", call, call + 1, reason.Expired},
		{"the origin a run window old", -run, 0, reason.OK},
		{"the origin past the run window", -run - 1, 0, reason.Expired},
		{"the origin a call window ahead", call, 0, reason.OK},
		{"the origin past a call window ahead", call + 1, 0, reason.Expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.stamps[0].TS = now + tt.origin
			s.stamps[1].TS = now + tt.last
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestFreshnessAtExtremeClocks checks that check 7's arithmetic is exact: a clock at either end of int64
// is never fresh for stamps at ts 0, though a wrapped difference would be.
func TestFreshnessAtExtremeClocks(t *testing.T) {
	tests := []struct {
		name string
		now  int64
		code reason.Code
	}{
		// A clock past every window the policy can have fails check 0 first.
		{"now = 2^63 - 1", math.MaxInt64, reason.PolicyExpired},
		{"now = -2^63", math.MinInt64, reason.Expired},
		{"now = -2^63 + 1", math.MinInt64 + 1, reason.Expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.stamps[0].TS = 0
			s.stamps[1].TS = 0
			s.cfg.Now = func() int64 { return tt.now }
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestNegativeWindows checks that a negative call window is never met, and that a negative run window is
// not met by an origin at now. (By the spec's words, an origin ahead of now is held to the call window
// only, so a negative run window does not refuse it.)
func TestNegativeWindows(t *testing.T) {
	for _, edit := range []func(*verify.Config){
		func(c *verify.Config) { c.CallMaxAgeMs = -1 },
		func(c *verify.Config) { c.CallMaxAgeMs = math.MinInt64 },
		func(c *verify.Config) { c.RunMaxAgeMs = -1 },
	} {
		s := mesh(t)
		for i := range s.stamps {
			s.stamps[i].TS = now
		}
		edit(&s.cfg)
		if got := s.run(t); got.Reason != reason.Expired {
			t.Fatalf("Verify = %+v, want EXPIRED", got)
		}
	}
}

// entries is influence the fixture's stamps do not commit to.
var entries = []influence.Entry{{Class: influence.Class("third-party"), Src: "web:example.com", H: "h1"}}

func entriesToken(t *testing.T, es []influence.Entry) string {
	t.Helper()
	b, err := influence.EntriesWire(es)
	if err != nil {
		t.Fatal(err)
	}
	return b64.Encode(b)
}

func commitment(t *testing.T, es []influence.Entry) string {
	t.Helper()
	c, err := influence.Commit(es)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestInfluence pins check 9: absent influence is the empty list, an empty token is not absent, and the
// last stamp commits to the influence that arrived.
func TestInfluence(t *testing.T) {
	tests := []struct {
		name  string
		infl  func(t *testing.T) string // the last stamp's
		token func(t *testing.T) *string
		code  reason.Code
	}{
		{"none, absent", none, func(*testing.T) *string { return nil }, reason.OK},
		{"none, as an empty list", none, func(*testing.T) *string { return ptr(b64.Encode([]byte("[]"))) }, reason.OK},
		{"none, as an empty token", none, func(*testing.T) *string { return ptr("") }, reason.InfluenceMismatch},
		{"some, committed", committed, func(t *testing.T) *string { return ptr(entriesToken(t, entries)) }, reason.OK},
		{"some, absent", committed, func(*testing.T) *string { return nil }, reason.InfluenceMismatch},
		{"some, not committed", none, func(t *testing.T) *string { return ptr(entriesToken(t, entries)) },
			reason.InfluenceMismatch},
		{"some, not wire bytes", committed, func(*testing.T) *string {
			return ptr(b64.Encode([]byte(`[ {"cls":"third-party","h":"h1","src":"web:example.com"}]`)))
		}, reason.InfluenceMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.stamps[1].Infl = tt.infl(t)
			s.in.Influence = tt.token(t)
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

func none(*testing.T) string        { return "" }
func committed(t *testing.T) string { return commitment(t, entries) }

// TestBinding pins check 8: the last stamp's bind equals the expected binding, "" included, and an
// absent expected binding matches nothing.
func TestBinding(t *testing.T) {
	tests := []struct {
		name     string
		bind     string
		expected *string
		code     reason.Code
	}{
		{"the binding", "bind-1", ptr("bind-1"), reason.OK},
		{"an empty binding", "", ptr(""), reason.OK},
		{"an empty binding, none expected", "", nil, reason.BindingMismatch},
		{"another binding than the empty one", "bind-1", ptr(""), reason.BindingMismatch},
		{"the empty binding for another", "", ptr("bind-1"), reason.BindingMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.stamps[1].Bind = tt.bind
			s.in.ExpectedBind = tt.expected
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestRoute pins check 11's proof handling.
func TestRoute(t *testing.T) {
	s := mesh(t)
	p, err := policy.ReadProof(*s.in.Proof)
	if err != nil {
		t.Fatal(err)
	}
	p.RootID = "v0"
	other, err := p.Token()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		proof *string
		code  reason.Code
	}{
		{"the route's proof", s.in.Proof, reason.OK},
		{"no proof", nil, reason.PathNotAllowed},
		{"an empty proof token", ptr(""), reason.PathNotAllowed},
		{"a proof naming another tree", &other, reason.PathNotAllowed},
		{"a proof that does not read", ptr(b64.Encode([]byte("{}"))), reason.PathNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.in.Proof = tt.proof
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestReplay pins check 10: the second use of a key is a replay, while another key, the empty one
// included, is not on its first use; and a cache whose TTL is under twice the call window refuses every
// key, the window's double past int64 included.
func TestReplay(t *testing.T) {
	s := mesh(t)
	s.in.Chain = ptr(s.token(t))
	s.stamps = nil
	v := verify.New(s.cfg)
	for i, want := range []reason.Code{reason.OK, reason.Replay, reason.Replay} {
		if got, err := v.Verify(t.Context(), s.in); err != nil || got.Reason != want {
			t.Fatalf("use %d: Verify = %+v, %v, want %s", i+1, got, err, want)
		}
	}
	for _, key := range []string{"rid-1|orders|resp", ""} { // an empty key is a key, not an absent one
		s.in.NonceKey = ptr(key)
		for i, want := range []reason.Code{reason.OK, reason.Replay} {
			if got, err := v.Verify(t.Context(), s.in); err != nil || got.Reason != want {
				t.Fatalf("the key %q, use %d: Verify = %+v, %v, want %s", key, i+1, got, err, want)
			}
		}
	}

	tests := []struct {
		name      string
		ttl, call int64
		code      reason.Code
	}{
		{"a TTL of twice the window", 2 * verify.CallMaxAgeMs, verify.CallMaxAgeMs, reason.OK},
		{"a TTL of twice the window and 1 ms", 2*verify.CallMaxAgeMs + 1, verify.CallMaxAgeMs, reason.OK},
		{"a TTL 1 ms short", 2*verify.CallMaxAgeMs - 1, verify.CallMaxAgeMs, reason.Replay},
		{"a TTL of 0 for a window of 0", 0, 0, reason.OK},
		{"a TTL of -1 for a window of 0", -1, 0, reason.Replay},
		{"a TTL of -2^63 for a window of 0", math.MinInt64, 0, reason.Replay},
		{"a TTL of 2^63 - 1 for a window past 2^62", math.MaxInt64, math.MaxInt64/2 + 1, reason.Replay},
		{"a TTL of 2^63 - 1 for a window of 2^62 - 1", math.MaxInt64, math.MaxInt64 / 2, reason.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			for i := range s.stamps {
				s.stamps[i].TS = now
			}
			s.cfg.CallMaxAgeMs = tt.call
			s.cfg.Nonces = verify.NewMemoryNonceCache(tt.ttl)
			if got := s.run(t); got.Reason != tt.code {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// recorder is a NonceCache that records the keys it is offered.
type recorder struct {
	ttl     int64
	offered []string
	err     error
}

func (r *recorder) SeenBefore(_ context.Context, key string, now int64) (bool, error) {
	r.offered = append(r.offered, key)
	return false, r.err
}

func (r *recorder) TTL() int64 { return r.ttl }

// TestNonceSpending checks which results spend the nonce key: only those that reach check 10 with a key
// and a cache that remembers long enough. POLICY_EXPIRED spends none.
func TestNonceSpending(t *testing.T) {
	tests := []struct {
		name  string
		make  func(*setup)
		spent bool
	}{
		{"OK", func(*setup) {}, true},
		{"policy expired", func(s *setup) { s.cfg.PolicyNotAfter = now - 1 }, false},
		{"influence not committed", func(s *setup) { s.in.Influence = ptr("") }, false},
		{"no nonce key", func(s *setup) { s.in.NonceKey = nil }, false},
		{"a cache that forgets too soon", func(s *setup) { s.cfg.Nonces.(*recorder).ttl = 2*verify.CallMaxAgeMs - 1 }, false},
		{"no proof", func(s *setup) { s.in.Proof = nil }, true},
		{"another peer", func(s *setup) { s.in.Peer = &verify.Peer{Svc: "search"} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			r := &recorder{ttl: verify.NonceTTLMs}
			s.cfg.Nonces = r
			tt.make(s)
			s.run(t)
			var want []string
			if tt.spent {
				want = []string{"rid-1|orders|req"}
			}
			if !slices.Equal(r.offered, want) {
				t.Fatalf("the cache was offered %q, want %q", r.offered, want)
			}
		})
	}
}

// TestNonceCacheFailure checks that a cache that can't answer makes Verify fail with its error, and a
// zero Result, which is not OK.
func TestNonceCacheFailure(t *testing.T) {
	s := mesh(t)
	down := errors.New("the store is down")
	s.cfg.Nonces = &recorder{ttl: verify.NonceTTLMs, err: down}
	s.in.Peer = &verify.Peer{Svc: "orders", Inst: "10.0.0.7"}
	s.in.Chain = ptr(s.token(t))
	got, err := verify.New(s.cfg).Verify(t.Context(), s.in)
	if !errors.Is(err, down) {
		t.Fatalf("Verify error = %v, want %v", err, down)
	}
	if got != (verify.Result{}) || got.OK() {
		t.Fatalf("Verify = %+v with the error, want the zero Result", got)
	}
}

// store is a NonceCache that, as one backed by a store would, answers with ctx's error once ctx is done.
type store struct{ recorder }

func (s *store) SeenBefore(ctx context.Context, key string, now int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return s.recorder.SeenBefore(ctx, key, now)
}

// TestCancelledContext checks that Verify hands its ctx to the nonce cache: a cache that honours a
// cancelled ctx makes Verify fail with its error and the zero Result, while a live ctx verifies.
func TestCancelledContext(t *testing.T) {
	s := mesh(t)
	s.cfg.Nonces = &store{recorder{ttl: verify.NonceTTLMs}}
	s.in.Chain = ptr(s.token(t))
	v := verify.New(s.cfg)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := v.Verify(ctx, s.in)
	if !errors.Is(err, context.Canceled) || got != (verify.Result{}) {
		t.Fatalf("Verify = %+v, %v under a cancelled ctx, want the zero Result and %v", got, err, context.Canceled)
	}
	if got, err := v.Verify(t.Context(), s.in); err != nil || !got.OK() {
		t.Fatalf("Verify = %+v, %v under a live ctx, want OK", got, err)
	}
}

// TestNewCopiesConfig checks that a verifier keeps its own copy of the Config's keyring, its keys
// included, root and origins.
func TestNewCopiesConfig(t *testing.T) {
	s := mesh(t)
	s.in.Chain = ptr(s.token(t))
	v := verify.New(s.cfg)
	s.cfg.Keyring["orders"] = pub(t, "pi")
	s.cfg.Keyring["gateway"][0] ^= 1
	s.cfg.Root[0] ^= 1
	s.cfg.AllowedOrigins[0] = "orders"
	if got, err := v.Verify(t.Context(), s.in); err != nil || !got.OK() {
		t.Fatalf("Verify = %+v, %v after the Config changed, want OK", got, err)
	}
}

// TestNewRefusesAnIncompleteConfig checks that New panics without a clock or a nonce cache, which no
// check can do without.
func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for name, edit := range map[string]func(*verify.Config){
		"no clock":       func(c *verify.Config) { c.Now = nil },
		"no nonce cache": func(c *verify.Config) { c.Nonces = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := mesh(t).cfg
			edit(&cfg)
			defer func() {
				if recover() == nil {
					t.Fatal("New did not panic")
				}
			}()
			verify.New(cfg)
		})
	}
}

// TestResult pins OK.
func TestResult(t *testing.T) {
	if !(verify.Result{Reason: reason.OK}).OK() {
		t.Fatal("an OK result is not OK")
	}
	for _, code := range []reason.Code{"", reason.PathNotAllowed, reason.PolicyExpired, "ok"} {
		if (verify.Result{Reason: code, SuspectSvc: "orders"}).OK() {
			t.Fatalf("a %q result is OK", code)
		}
	}
}

// TestWindows pins the spec's windows and NonceTTLFor.
func TestWindows(t *testing.T) {
	if verify.CallMaxAgeMs != 5000 || verify.RunMaxAgeMs != 1800000 || verify.NonceTTLMs != 15000 {
		t.Fatal("the windows are not the spec's")
	}
	for call, want := range map[int64]int64{
		math.MinInt64:       verify.NonceTTLMs,
		-1:                  verify.NonceTTLMs,
		0:                   verify.NonceTTLMs,
		5000:                verify.NonceTTLMs,
		7500:                verify.NonceTTLMs,
		7501:                15002,
		10000:               20000,
		math.MaxInt64 / 2:   math.MaxInt64 - 1,
		math.MaxInt64/2 + 1: math.MaxInt64,
		math.MaxInt64:       math.MaxInt64,
	} {
		if got := verify.NonceTTLFor(call); got != want {
			t.Errorf("NonceTTLFor(%d) = %d, want %d", call, got, want)
		}
	}
}

// signedPolicy returns a keyring of gateway's, orders' and pi's keys and the mesh root, each signed by
// the policy key of signer until its notAfter, and the pin of client-policy.
func signedPolicy(
	t *testing.T, signer string, keyringNotAfter, rootNotAfter int64,
) (policy.KeyringFile, policy.Root, string) {
	t.Helper()
	priv, _ := vectors.V3Key(t, signer)
	policyPub := keys.EncodePublic(priv.Public().(ed25519.PublicKey))
	services := map[string]string{}
	for _, svc := range []string{"gateway", "orders", "pi"} {
		services[svc] = keys.EncodePublic(pub(t, svc))
	}
	kf, err := policy.SignKeyring(services, policyPub, keyringNotAfter, priv)
	if err != nil {
		t.Fatal(err)
	}
	s := mesh(t)
	root, err := policy.SignRoot(s.cfg.Root, s.cfg.RootID, rootNotAfter, priv)
	if err != nil {
		t.Fatal(err)
	}
	return kf, root, keys.EncodePublic(pub(t, "client-policy"))
}

// pinnedConfig is the Config a caller hands Pinned: everything but the pinned material, set by name, and
// material of its own that Pinned replaces.
func pinnedConfig(t *testing.T, s *setup) verify.Config {
	return verify.Config{
		Keyring:        policy.Keyring{"other": pub(t, "orders")},
		Root:           []byte("other"),
		RootID:         "other",
		PolicyNotAfter: -1,
		AllowedOrigins: []string{"gateway"},
		Sess:           "sess-2",
		Nonces:         s.cfg.Nonces,
		Now:            s.cfg.Now,
		CallMaxAgeMs:   pinnedCallMaxAgeMs,
		RunMaxAgeMs:    pinnedRunMaxAgeMs,
	}
}

// The windows pinnedConfig sets, neither the default, so that Pinned resetting them is seen.
const (
	pinnedCallMaxAgeMs = verify.CallMaxAgeMs + 1000
	pinnedRunMaxAgeMs  = verify.RunMaxAgeMs + 1000
)

// TestPinned checks that Pinned fills a Config that verifies from material the pin vouches for, with the
// earlier window as PolicyNotAfter, and keeps everything else the caller set.
func TestPinned(t *testing.T) {
	for _, w := range [][2]int64{{now + 10, now + 20}, {now + 20, now + 10}, {now, now}} {
		kf, root, pin := signedPolicy(t, "client-policy", w[0], w[1])
		s := mesh(t)
		for i := range s.stamps {
			s.stamps[i].Sess = "sess-2"
		}
		cfg, err := verify.Pinned(kf, root, pin, pinnedConfig(t, s))
		if err != nil {
			t.Fatalf("Pinned: %v", err)
		}
		if want := min(w[0], w[1]); cfg.PolicyNotAfter != want {
			t.Fatalf("PolicyNotAfter = %d, want %d", cfg.PolicyNotAfter, want)
		}
		if !bytes.Equal(cfg.Root, s.cfg.Root) || cfg.RootID != s.cfg.RootID || len(cfg.Keyring) != 3 ||
			!cfg.Keyring["orders"].Equal(pub(t, "orders")) || cfg.CallMaxAgeMs != pinnedCallMaxAgeMs ||
			cfg.RunMaxAgeMs != pinnedRunMaxAgeMs || cfg.Sess != "sess-2" ||
			!slices.Equal(cfg.AllowedOrigins, []string{"gateway"}) {
			t.Fatalf("Pinned = %+v", cfg)
		}
		s.cfg = cfg
		if got := s.run(t); got != s.named(reason.OK) {
			t.Fatalf("Verify = %+v under the pinned Config", got)
		}
	}
}

// TestPinnedRefuses checks that Pinned refuses material the pin does not vouch for now, naming it.
func TestPinnedRefuses(t *testing.T) {
	good := func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
		return signedPolicy(t, "client-policy", now, now)
	}
	tests := []struct {
		name  string
		make  func(t *testing.T) (policy.KeyringFile, policy.Root, string)
		names string
	}{
		{"a keyring under another policy key", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, _, pin := signedPolicy(t, "server-policy", now, now)
			_, root, _ := good(t)
			return kf, root, pin
		}, "keyring"},
		{"a keyring with a bad signature", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, root, pin := good(t)
			kf.NotAfter++
			return kf, root, pin
		}, "keyring"},
		{"an expired keyring", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, _, pin := signedPolicy(t, "client-policy", now-1, now)
			return kf, mustRoot(good(t)), pin
		}, "keyring"},
		{"a pin that is not a key", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, root, _ := good(t)
			return kf, root, "AAAA"
		}, "keyring"},
		{"a root under another policy key", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, _, pin := good(t)
			_, root, _ := signedPolicy(t, "server-policy", now, now)
			return kf, root, pin
		}, "root"},
		{"an expired root", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, root, pin := signedPolicy(t, "client-policy", now, now-1)
			return kf, root, pin
		}, "root"},
		{"a root that is not base64url", func(t *testing.T) (policy.KeyringFile, policy.Root, string) {
			kf, root, pin := good(t)
			priv, _ := vectors.V3Key(t, "client-policy")
			root.Root = "not base64url"
			msg, err := policy.RootSigningBytes(root.RootID, root.Root, root.NotAfter)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := keys.Sign(priv, msg)
			if err != nil {
				t.Fatal(err)
			}
			root.Sig = b64.Encode(sig)
			return kf, root, pin
		}, "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kf, root, pin := tt.make(t)
			s := mesh(t)
			_, err := verify.Pinned(kf, root, pin, pinnedConfig(t, s))
			if err == nil || !strings.Contains(err.Error(), tt.names) {
				t.Fatalf("Pinned error = %v, want one naming the %s", err, tt.names)
			}
		})
	}
	t.Run("no clock or nonce cache", func(t *testing.T) {
		kf, root, pin := good(t)
		s := mesh(t)
		if _, err := verify.Pinned(kf, root, pin, verify.Config{Nonces: s.cfg.Nonces}); err == nil {
			t.Fatal("Pinned took no clock")
		}
		if _, err := verify.Pinned(kf, root, pin, verify.Config{Now: s.cfg.Now}); err == nil {
			t.Fatal("Pinned took no nonce cache")
		}
	})
}

func mustRoot(_ policy.KeyringFile, root policy.Root, _ string) policy.Root { return root }
