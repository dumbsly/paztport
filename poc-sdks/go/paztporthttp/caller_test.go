// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// TestReceiversName names a receiver by its host, ignoring the port and the host's case, keeping a
// trailing dot and an IPv6 address's brackets, and gives an unmapped host as itself, in lower case.
func TestReceiversName(t *testing.T) {
	r, err := paztporthttp.NewReceivers(map[string]string{
		"pay.internal": "payment", "Orders.Internal": "orders", "[::1]": "local", "10.0.0.7": "ledger",
	})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"pay.internal":         "payment",
		"pay.internal:8443":    "payment",
		"PAY.Internal:8443":    "payment",
		"orders.internal":      "orders",
		"ORDERS.INTERNAL":      "orders",
		"[::1]":                "local",
		"[::1]:8443":           "local",
		"10.0.0.7:80":          "ledger",
		"pay.internal.":        "pay.internal.",
		"pay.internal.:8443":   "pay.internal.",
		"[::2]:8443":           "[::2]",
		"Catalogue":            "catalogue",
		"CATALOGUE.:8443":      "catalogue.",
		"[FE80::1]:8443":       "[fe80::1]",
		"catalogue:80":         "catalogue",
		"pay.internal.example": "pay.internal.example",
		"":                     "",
	} {
		if got := r.Name(host); got != want {
			t.Errorf("Name(%q) = %q, want %q", host, got, want)
		}
	}
	var none paztporthttp.Receivers
	if got := none.Name("payment:8443"); got != "payment" {
		t.Errorf("with no mapping, Name = %q, want payment", got)
	}
}

// TestNewReceiversRefuses refuses a blank host or name, two hosts differing only in case, and a host Name
// could never match, one with a port or an unbracketed colon, naming the problem but never the host.
func TestNewReceiversRefuses(t *testing.T) {
	for _, m := range []map[string]string{
		{"": "payment"},
		{" \t": "payment"},
		{"pay.internal": ""},
		{"pay.internal": " "},
		{"Pay.Internal": "payment", "pay.internal": "payment"},
		{"pay.internal:8443": "payment"},
		{"pay.internal:": "payment"},
		{"[pay.internal]:8443": "payment"},
		{"pay.internal::1": "payment"},
	} {
		r, err := paztporthttp.NewReceivers(m)
		if err == nil {
			t.Errorf("NewReceivers(%q) = %v", m, r)
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), "pay.internal") {
			t.Errorf("the error %q echoes the host", err)
		}
	}
}

// TestNewReceiversCopies keeps its own copy of the mapping, so the map it was given may change after.
func TestNewReceiversCopies(t *testing.T) {
	m := map[string]string{"pay.internal": "payment"}
	r, err := paztporthttp.NewReceivers(m)
	if err != nil {
		t.Fatal(err)
	}
	m["pay.internal"] = "other"
	if got := r.Name("pay.internal"); got != "payment" {
		t.Fatalf("after the map changed, Name = %q", got)
	}
}

// originCaller returns a gateway that is an origin, with a proof for gateway/orders only, and that proof.
func originCaller(t *testing.T) (*paztporthttp.Caller, ed25519.PublicKey, policy.Proof) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := policy.Proof{LeafSalt: make([]byte, 16), Siblings: [][]byte{make([]byte, 32)}, Dirs: "L", RootID: "r"}
	return &paztporthttp.Caller{
		Stamper: &stamp.Stamper{
			Svc: "gateway", Inst: "gw-1", Key: priv, Origin: true,
			NewRID: func() string { return "rid-1" }, Now: func() int64 { return 1767225600000 },
		},
		Bundle: policy.ProofBundle{Service: "gateway", RootID: "r", Proofs: map[string]policy.Proof{"gateway/orders": proof}},
	}, pub, proof
}

// TestCallerExtProcOrigin stamps as a gateway's external processor does, an origin with no inbound
// chain and no influence: exactly X-Path-Chain, holding the one origin stamp, then X-Path-Proof, and no
// X-Path-Proof for a route the bundle holds no proof for.
func TestCallerExtProcOrigin(t *testing.T) {
	caller, pub, proof := originCaller(t)
	body := []byte(`{"qty":1}`)
	o, err := caller.Stamp("POST", "/orders/7?x=%2F", "orders", body, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Headers) != 2 || o.Headers[0].Name != wire.Chain || o.Headers[1].Name != wire.Proof {
		t.Fatalf("Headers = %+v, want exactly X-Path-Chain then X-Path-Proof", o.Headers)
	}
	sent, code := stamp.ReadChain(o.Headers[0].Value)
	if code != reason.OK || !slices.Equal(sent, o.Sent) || len(sent) != 1 {
		t.Fatalf("the chain header reads as %+v (%s), Sent %+v", sent, code, o.Sent)
	}
	bind, err := wire.Bind("POST", "/orders/7?x=%2F", body)
	if err != nil {
		t.Fatal(err)
	}
	s := sent[0]
	if s.Svc != "gateway" || s.Inst != "gw-1" || s.RID != "rid-1" || s.TS != 1767225600000 || s.Sess != "" ||
		s.Rcv != "orders" || s.Bind != bind || s.Infl != "" || s.Prev != "" {
		t.Fatalf("the origin stamp is %+v", s)
	}
	msg, err := s.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Sig)
	if err != nil || !keys.Verify(pub, msg, sig) {
		t.Fatal("the origin stamp's signature does not verify under the gateway's key")
	}
	wantProof, err := wire.EncodeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if o.Headers[1].Value != wantProof || o.Proof == nil || o.Receiver != "orders" {
		t.Fatalf("the proof header %q, Proof %v, Receiver %q", o.Headers[1].Value, o.Proof, o.Receiver)
	}

	o, err = caller.Stamp("GET", "/statements", "ledger", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Headers) != 1 || o.Headers[0].Name != wire.Chain || o.Proof != nil {
		t.Fatalf("with no proof for the route: Headers = %+v, Proof %v", o.Headers, o.Proof)
	}
}

// TestCallerStampBindsTheTarget binds the target as Bind does, a bare trailing "?" left out, and refuses
// a target or method with no UTF-8 form, which gives no binding.
func TestCallerStampBindsTheTarget(t *testing.T) {
	caller, _, _ := originCaller(t)
	o, err := caller.Stamp("GET", "/pay?", "orders", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := wire.Bind("GET", "/pay", nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.Sent[0].Bind != bind {
		t.Fatalf("/pay? binds as %s, /pay as %s", o.Sent[0].Bind, bind)
	}
	for _, tc := range []struct{ method, target string }{{"GET", "/p\xff"}, {"GET", "/p\xed\xa0\x80"}, {"G\xffT", "/p"}} {
		o, err := caller.Stamp(tc.method, tc.target, "orders", nil, nil, nil)
		if err == nil {
			t.Errorf("Stamp(%q, %q) = %+v, want an error", tc.method, tc.target, o)
		}
		if o.Headers != nil || o.Sent != nil {
			t.Errorf("Stamp(%q, %q) with an error gave %+v", tc.method, tc.target, o)
		}
	}
}

// TestCallerStampLeavesItsInputs never writes into the inbound chain's or the influence's backing
// arrays, even where they have room.
func TestCallerStampLeavesItsInputs(t *testing.T) {
	c := callerCase(t, "each label becomes an entry")
	chain := chainOf(c.Get("inbound"))
	inbound := append(make(stamp.Chain, 0, len(chain)+1), chain...)
	infl := entries(c.Get("influence"))
	spare := append(make([]influence.Entry, 0, len(infl)+1), infl...)
	priv, _ := vectors.RulesKey(t, "orders")
	caller := &paztporthttp.Caller{Stamper: &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: priv,
		Now: func() int64 { return 1767225599500 }}}
	o, err := caller.Stamp("POST", "/pay", "payment", nil, inbound, spare)
	if err != nil {
		t.Fatal(err)
	}
	if inbound[:cap(inbound)][len(inbound)] != (stamp.Stamp{}) || spare[:cap(spare)][len(spare)] != (influence.Entry{}) {
		t.Fatal("Stamp wrote past the end of a slice it was given")
	}
	if !slices.Equal(inbound, chain) || !slices.Equal(spare, infl) || len(o.Sent) != len(chain)+1 {
		t.Fatalf("Stamp changed its inputs, or sent %d stamps", len(o.Sent))
	}
}

// TestCallerCheckWithNoVerifier checks nothing, and counts any response as one local-untrusted entry
// from the receiver, by its result hash.
func TestCallerCheckWithNoVerifier(t *testing.T) {
	caller, _, _ := originCaller(t)
	o, err := caller.Stamp("GET", "/orders/7", "orders", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":7}`)
	got, err := caller.Check(t.Context(), o, 200, "anything", body)
	if err != nil {
		t.Fatal(err)
	}
	want := []influence.Entry{{Class: influence.LocalUntrusted, Src: "http:orders", H: wire.ResultHash(200, body)}}
	if got.Check != nil || !slices.Equal(got.Entries, want) {
		t.Fatalf("Check = %+v, want no check and %+v", got, want)
	}
}
