// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// FuzzServiceOf reads any bytes as a client certificate, seeded with the rules' peer certificates. It
// never panics, PeerFromCertificate names the same service ServiceOf does, and a service or issuer it
// gives is UTF-8 text.
func FuzzServiceOf(f *testing.F) {
	vectors.Rules(f).Get("peerCertificates").Each(func(_ string, c vectors.Node) {
		der, err := hex.DecodeString(c.Get("certificate").Str())
		if err != nil {
			f.Fatalf("certificate: %v", err)
		}
		f.Add(der)
	})
	vectors.Rules(f).Get("peers").Each(func(name string, _ vectors.Node) {
		der, _ := vectors.RulesPeer(f, name)
		f.Add(der)
	})
	f.Fuzz(func(t *testing.T, der []byte) {
		svc := paztporthttp.ServiceOf(der)
		p := paztporthttp.PeerFromCertificate(der, "10.0.0.1")
		if p.Peer.Svc != svc || p.Peer.Inst != "10.0.0.1" {
			t.Fatalf("PeerFromCertificate = %+v, ServiceOf = %q", p, svc)
		}
		if !utf8.ValidString(svc) || !utf8.ValidString(p.Issuer) {
			t.Fatalf("the service %q or issuer %q is not UTF-8", svc, p.Issuer)
		}
	})
}

// fuzzPeers returns the rules' client certificates, as PeerFromCertificate reads them, and nil last, for
// no certificate; a fuzzed index picks one.
func fuzzPeers(f *testing.F) []*paztporthttp.PeerCert {
	var peers []*paztporthttp.PeerCert
	for _, name := range vectors.Rules(f).Get("peers").Names() {
		der, addr := vectors.RulesPeer(f, name)
		p := paztporthttp.PeerFromCertificate(der, addr)
		peers = append(peers, &p)
	}
	return append(peers, nil)
}

// peerIndex returns the index fuzzPeers gives the peer called name, or that of nil for no name.
func peerIndex(f *testing.F, n vectors.Node) uint8 {
	names := vectors.Rules(f).Get("peers").Names()
	if n.IsNull() {
		return uint8(len(names))
	}
	for i, name := range names {
		if name == n.Str() {
			return uint8(i)
		}
	}
	f.Fatalf("no peer is called %q", n.Str())
	return 0
}

// FuzzServeHandshake serves any body from any of the rules' peers, or none, seeded with every handshake
// body of the rules and of their partner cases. It never panics, and its answer is 200 with a reply that
// reads, attested or unsafe, or 400 with exactly one of the two error bodies.
func FuzzServeHandshake(f *testing.F) {
	partner := vectors.Rules(f).Get("sessionHeader").Index(0).Get("partner")
	now := partner.Get("start").Int()
	cfg := partnerConfig(f, partner, func() int64 { return now })
	peers := fuzzPeers(f)
	vectors.Rules(f).Get("handshakeBodies").Each(func(name string, _ vectors.Node) {
		for i := range peers {
			f.Add(vectors.RulesHandshakeBody(f, name), uint8(i))
		}
	})
	vectors.Rules(f).Get("handshakeErrors").Each(func(_ string, c vectors.Node) {
		c.Get("steps").Each(func(_ string, step vectors.Node) {
			if h := step.Get("handshake"); step.Has("handshake") && !h.Get("request").IsNull() {
				f.Add(vectors.RulesHandshakeBody(f, h.Get("request").Str()), peerIndex(f, h.Get("peer")))
			} else if step.Has("handshake") {
				f.Add(h.Get("body").Hex(), peerIndex(f, h.Get("peer")))
			}
		})
	})
	f.Fuzz(func(t *testing.T, body []byte, peer uint8) {
		s, err := paztporthttp.NewSessions(cfg)
		if err != nil {
			t.Fatalf("NewSessions: %v", err)
		}
		a := s.ServeHandshake(body, peers[int(peer)%len(peers)])
		switch a.Status {
		case 200:
			r, err := session.ParseReply(a.Body)
			if err != nil {
				t.Fatalf("a 200 whose body is no reply: %v", err)
			}
			if r.Status != session.StatusAttested && r.Status != session.StatusUnsafe {
				t.Fatalf("a reply with status %q", r.Status)
			}
		case 400:
			if b := string(a.Body); b != `{"error":"INVALID_PARAMS"}` && b != `{"error":"NO_SESSION"}` {
				t.Fatalf("a 400 with body %s", b)
			}
		default:
			t.Fatalf("answered %d %s", a.Status, a.Body)
		}
	})
}

// FuzzSessionsAccept decides any call from any of the rules' peers, or none, in a partner that has just
// opened an attested session for the shop, seeded with the calls of the rules' partner cases. A call may
// name that session and carry a boundary stamp signed in it over the call's own method, target and body,
// so that the fuzzer reaches the session's verifier with a chain that verifies. It never panics, and its
// answer keeps the partner's rules: a refusal is 403 and carries nothing, an attested call carries the
// chain that verified, and any other call carries neither chain nor influence.
func FuzzSessionsAccept(f *testing.F) {
	c := vectors.Rules(f).Get("sessionHeader").Index(1)
	partner := c.Get("partner")
	handshake, call := c.Get("steps").Index(0), c.Get("steps").Index(1)
	template := call.Get("call").Get("stamp")
	handshakeAt, callAt := handshake.Get("at").Int(), call.Get("at").Int()
	var now int64
	cfg := partnerConfig(f, partner, func() int64 { return now })
	ttl := partner.Get("nonceTtlMs").Int()
	body := vectors.RulesHandshakeBody(f, handshake.Get("handshake").Get("request").Str())
	shop := partnerPeer(f, handshake.Get("handshake").Get("peer"))
	peers := fuzzPeers(f)

	// flags: 1 names the session just opened, 2 signs a boundary stamp in it.
	for _, kind := range []string{"sessionHeader", "sessionRegistry", "sessionExpiry", "boundaryRefusals"} {
		vectors.Rules(f).Get(kind).Each(func(_ string, k vectors.Node) {
			k.Get("steps").Each(func(_ string, step vectors.Node) {
				if !step.Has("call") {
					return
				}
				cl := step.Get("call")
				var flags uint8
				var sess, proof, infl string
				if ref := cl.Get("session"); !ref.IsNull() && ref.Has("id") {
					sess = ref.Get("id").Str()
				} else if !ref.IsNull() {
					flags |= 1
				}
				if !cl.Get("stamp").IsNull() {
					flags |= 2
				}
				if h := cl.Get("proofHeader"); !h.IsNull() {
					proof = h.Str()
				}
				if h := cl.Get("influenceHeader"); !h.IsNull() {
					infl = h.Str()
				}
				f.Add(cl.Get("method").Str(), cl.Get("target").Str(), cl.Get("body").Hex(), "", proof, infl, sess,
					flags, peerIndex(f, cl.Get("peer")))
			})
		})
	}
	f.Add("POST", "/charge", []byte{}, "W10", "ew", "not*base64url", " \t", uint8(1), uint8(0))
	f.Fuzz(func(t *testing.T, method, target string, reqBody []byte, chain, proof, infl, sess string,
		flags, peer uint8) {
		live := cfg
		live.Nonces = verify.NewMemoryNonceCache(ttl)
		s, err := paztporthttp.NewSessions(live)
		if err != nil {
			t.Fatalf("NewSessions: %v", err)
		}
		now = handshakeAt
		a := s.ServeHandshake(body, shop)
		r, err := session.ParseReply(a.Body)
		if a.Status != 200 || err != nil || r.Status != session.StatusAttested {
			t.Fatalf("the handshake is answered %d %s", a.Status, a.Body)
		}
		now = callAt
		if flags&1 != 0 {
			sess = r.Sess
		}
		if bind, err := wire.Bind(method, target, reqBody); err == nil && flags&2 != 0 {
			chain = signBoundary(t, template.With(t), r.Sess, bind)
		}
		req := paztporthttp.InboundRequest{Method: method, Target: target, Chain: chain, Proof: proof,
			Influence: infl, Session: sess, Body: reqBody}
		pa, err := s.Accept(t.Context(), req, peers[int(peer)%len(peers)])
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		switch {
		case pa.Refusal != nil:
			if pa.Refusal.Status != 403 || !strings.HasPrefix(string(pa.Refusal.Body), `{"reason":"`) ||
				pa.Attested || pa.Chain != nil || len(pa.Influence) != 0 {
				t.Fatalf("a refusal %d %s carries %+v", pa.Refusal.Status, pa.Refusal.Body, pa)
			}
		case pa.Attested:
			if pa.Chain == nil || pa.Result == nil || !pa.Result.OK() {
				t.Fatalf("an attested call with chain %v and result %v", pa.Chain, pa.Result)
			}
		default:
			if pa.Chain != nil || len(pa.Influence) != 0 {
				t.Fatalf("an unattested call carries chain %v and influence %v", pa.Chain, pa.Influence)
			}
		}
	})
}
