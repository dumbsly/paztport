// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
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

// TestPeerCertificatesVectors replays the rules' peerCertificates: the peer a client certificate names,
// by the spec's walk of its subject, connected from remoteAddr.
func TestPeerCertificatesVectors(t *testing.T) {
	cases := vectors.Rules(t).Get("peerCertificates")
	if cases.Len() != 15 {
		t.Fatalf("the rules have %d peerCertificates cases, want 15", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			der, err := hex.DecodeString(c.Get("certificate").Str())
			if err != nil {
				t.Fatalf("certificate: %v", err)
			}
			got := paztporthttp.PeerFromCertificate(der, c.Get("remoteAddr").Str())
			want := verify.Peer{Svc: c.Get("expected").Get("svc").Str(), Inst: c.Get("expected").Get("inst").Str()}
			if got.Peer != want {
				t.Fatalf("Peer = %+v, want %+v", got.Peer, want)
			}
			if svc := paztporthttp.ServiceOf(der); svc != want.Svc {
				t.Fatalf("ServiceOf = %q, want %q", svc, want.Svc)
			}
			// Every case is issued by shop CA, whatever its subject.
			if got.Issuer != "CN=shop CA,O=shop" {
				t.Fatalf("Issuer = %q", got.Issuer)
			}
		})
	})
}

// TestCallerInfluenceVectors replays the rules' callerInfluence: a call stamped by Caller.Stamp, then
// its response checked by Caller.Check, compared as {rcv, reason, influence}.
func TestCallerInfluenceVectors(t *testing.T) {
	cases := vectors.Rules(t).Get("callerInfluence")
	if cases.Len() != 9 {
		t.Fatalf("the rules have %d callerInfluence cases, want 9", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			caller, o := stampCallerCase(t, c, nil)
			r := c.Get("response")
			var header string
			if h := r.Get("header"); !h.IsNull() {
				header = h.Str()
			}
			body, err := hex.DecodeString(r.Get("body").Str())
			if err != nil {
				t.Fatalf("the response's body: %v", err)
			}
			got, err := caller.Check(t.Context(), o, header, int(r.Get("status").Int()), body)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			e := c.Get("expected")
			if last := o.Sent[len(o.Sent)-1]; last.Rcv != e.Get("rcv").Str() {
				t.Errorf("the stamp is for %q, want %q", last.Rcv, e.Get("rcv").Str())
			}
			wantReason := e.Get("reason")
			switch {
			case wantReason.IsNull() && got.Check != nil:
				t.Errorf("Check = %+v, want none", *got.Check)
			case !wantReason.IsNull() && got.Check == nil:
				t.Errorf("no check, want %s", wantReason.Str())
			case !wantReason.IsNull() && got.Check.Result.Reason != reason.Code(wantReason.Str()):
				t.Errorf("Reason = %s, want %s", got.Check.Result.Reason, wantReason.Str())
			}
			if want := entries(e.Get("influence")); !slices.Equal(got.Entries, want) {
				t.Errorf("Entries = %+v\nwant %+v", got.Entries, want)
			}
		})
	})
}

// TestCallerStampsInHeaderOrder sends a call that has a proof and influence with its headers ordered
// Chain, Proof, Influence, each the token of what was stamped.
func TestCallerStampsInHeaderOrder(t *testing.T) {
	c := callerCase(t, "each label becomes an entry")
	_, o := stampCallerCase(t, c, nil)
	infl := entries(c.Get("influence"))
	chain, err := wire.EncodeChain(o.Sent)
	if err != nil {
		t.Fatal(err)
	}
	if o.Proof == nil {
		t.Fatal("no proof was sent for gateway/orders/payment")
	}
	proof, err := wire.EncodeProof(*o.Proof)
	if err != nil {
		t.Fatal(err)
	}
	inflTok, err := wire.EncodeInfluence(infl)
	if err != nil || inflTok == "" {
		t.Fatalf("EncodeInfluence = %q, %v", inflTok, err)
	}
	want := []wire.Header{{Name: wire.Chain, Value: chain}, {Name: wire.Proof, Value: proof},
		{Name: wire.Influence, Value: inflTok}}
	if !slices.Equal(o.Headers, want) {
		t.Fatalf("Headers = %+v\nwant %+v", o.Headers, want)
	}
	bind, err := wire.Bind("POST", "/pay", []byte(`{"amount":100}`))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := influence.Commit(infl)
	if err != nil {
		t.Fatal(err)
	}
	last := o.Sent[len(o.Sent)-1]
	if len(o.Sent) != 2 || last.Bind != bind || last.Infl != commit || last.Svc != "orders" {
		t.Fatalf("Sent = %+v", o.Sent)
	}
}

// TestCallerCheckNonceCacheError hands back the nonce cache's error, with nothing else.
func TestCallerCheckNonceCacheError(t *testing.T) {
	c := callerCase(t, "each label becomes an entry")
	caller, o := stampCallerCase(t, c, failingNonces{})
	r := c.Get("response")
	body, err := hex.DecodeString(r.Get("body").Str())
	if err != nil {
		t.Fatal(err)
	}
	got, err := caller.Check(t.Context(), o, r.Get("header").Str(), int(r.Get("status").Int()), body)
	if err == nil || !strings.Contains(err.Error(), "the cache is down") {
		t.Fatalf("Check = %+v, %v, want the cache's error", got, err)
	}
	if got.Check != nil || got.Entries != nil {
		t.Fatalf("Check with an error = %+v, want nothing", got)
	}
}

// failingNonces is a nonce cache that cannot answer.
type failingNonces struct{}

func (failingNonces) SeenBefore(context.Context, string, int64) (bool, error) {
	return false, errors.New("the cache is down")
}

func (failingNonces) TTL() int64 { return 15000 }

// callerCase returns the callerInfluence case called name.
func callerCase(t *testing.T, name string) vectors.Node {
	t.Helper()
	var found vectors.Node
	ok := false
	vectors.Rules(t).Get("callerInfluence").Each(func(n string, c vectors.Node) {
		if n == name {
			found, ok = c.With(t), true
		}
	})
	if !ok {
		t.Fatalf("the rules have no callerInfluence case %q", name)
	}
	return found
}

// stampCallerCase builds case c's caller, its stamper's clock at ts and, when it has a verifier, one
// pinned to its material over nonces (a fresh cache when nil), and stamps the case's call: its URI split
// into the authority, whose host the case's receivers name, and the target as written. The tables the
// case's caller holds are the operations section's, by name.
func stampCallerCase(
	t *testing.T, c vectors.Node, nonces verify.NonceCache,
) (*paztporthttp.Caller, paztporthttp.Outbound) {
	t.Helper()
	cc := c.Get("caller")
	svc := cc.Get("svc").Str()
	ts := c.Get("ts").Int()
	priv, _ := vectors.RulesKey(t, svc)
	caller := &paztporthttp.Caller{
		Stamper: &stamp.Stamper{Svc: svc, Inst: cc.Get("inst").Str(), Key: priv, Now: func() int64 { return ts }},
		Bundle:  bundleOf(t, c),
	}
	if cc.Get("verifier").Bool() {
		if nonces == nil {
			nonces = verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int())
		}
		now := c.Get("now").Int()
		caller.Verifier = pinnedVerifier(t, c.Get("material").Str(), verify.Config{
			AllowedOrigins: c.Get("allowedOrigins").Strs(),
			Nonces:         nonces,
			Now:            func() int64 { return now },
			CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
		})
	}
	if tables := cc.Get("operations"); tables.Len() > 0 {
		caller.Operations = map[string]policy.OperationTable{}
		for _, name := range tables.Strs() {
			text := vectors.Load(t, "http-v3.json").Get("operations").Get(name).Get("file").Str()
			table, err := policy.ReadOperationTable([]byte(text))
			if err != nil {
				t.Fatalf("ReadOperationTable(%s): %v", name, err)
			}
			caller.Operations[table.Service] = table
		}
	}
	byHost := map[string]string{}
	rs := cc.Get("receivers")
	for _, host := range rs.Names() {
		byHost[host] = rs.Get(host).Str()
	}
	receivers, err := paztporthttp.NewReceivers(byHost)
	if err != nil {
		t.Fatalf("NewReceivers: %v", err)
	}
	call := c.Get("call")
	authority, target := splitURI(t, call.Get("uri").Str())
	body, err := hex.DecodeString(call.Get("body").Str())
	if err != nil {
		t.Fatalf("the call's body: %v", err)
	}
	name, named := receivers.Name(authority)
	if !named {
		t.Fatalf("the call's host %q has no receiver name", authority)
	}
	o, err := caller.Stamp(call.Get("method").Str(), target, name, body,
		chainOf(c.Get("inbound")), entries(c.Get("influence")))
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	return caller, o
}

// splitURI splits an absolute URI into its authority and its target as written: everything from the
// first "/" after the authority, up to any "#".
func splitURI(t *testing.T, uri string) (authority, target string) {
	t.Helper()
	_, rest, ok := strings.Cut(uri, "://")
	if !ok {
		t.Fatalf("the call's URI %q has no authority", uri)
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		t.Fatalf("the call's URI %q has no path", uri)
	}
	target, _, _ = strings.Cut(rest[slash:], "#")
	return rest[:slash], target
}

// bundleOf returns the proof bundle of case c's caller: every route proof its material holds, read by
// the SDK's own bundle reader from a file made of the vector's own JSON text, the caller's name, the
// root's rootId and the proofs as the file writes them.
func bundleOf(t *testing.T, c vectors.Node) policy.ProofBundle {
	t.Helper()
	m := vectors.Rules(t).Get("material").Get(c.Get("material").Str())
	file := bytes.Join([][]byte{
		[]byte(`{"service":`), c.Get("caller").Get("svc").Raw(),
		[]byte(`,"rootId":`), m.Get("root").Get("rootId").Raw(),
		[]byte(`,"proofs":`), m.Get("proofs").Raw(),
		[]byte(`}`),
	}, nil)
	b, err := policy.ParseProofBundleFile(file)
	if err != nil {
		t.Fatalf("ParseProofBundleFile: %v", err)
	}
	if len(b.Proofs) != m.Get("proofs").Len() {
		t.Fatalf("the bundle holds %d proofs, the material %d", len(b.Proofs), m.Get("proofs").Len())
	}
	return b
}

// chainOf returns the stamps n lists.
func chainOf(n vectors.Node) stamp.Chain {
	c := make(stamp.Chain, n.Len())
	for i := range c {
		s := n.Index(i)
		c[i] = stamp.Stamp{
			Svc: s.Get("svc").Str(), Inst: s.Get("inst").Str(), RID: s.Get("rid").Str(), TS: s.Get("ts").Int(),
			Sess: s.Get("sess").Str(), Rcv: s.Get("rcv").Str(), Bind: s.Get("bind").Str(),
			Infl: s.Get("infl").Str(), Prev: s.Get("prev").Str(), Sig: s.Get("sig").Str(),
		}
	}
	return c
}
