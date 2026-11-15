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
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
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
	} {
		if got, ok := r.Name(host); !ok || got != want {
			t.Errorf("Name(%q) = %q, %t, want %q, true", host, got, ok, want)
		}
	}
	for _, host := range []string{"", ":8080"} {
		if got, ok := r.Name(host); ok || got != "" {
			t.Errorf("Name(%q) = %q, %t, want no name: a host with no name is no receiver", host, got, ok)
		}
	}
	var none paztporthttp.Receivers
	if got, ok := none.Name("payment:8443"); !ok || got != "payment" {
		t.Errorf("with no mapping, Name = %q, %t, want payment, true", got, ok)
	}
}

// TestReceiversNameUnmappedASCII lower-cases only ASCII letters of an unmapped host, and a mapped host is
// found by its ASCII lower case alone.
func TestReceiversNameUnmappedASCII(t *testing.T) {
	r, err := paztporthttp.NewReceivers(map[string]string{"kafka": "broker"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"Catalogue.Internal:80": "catalogue.internal",
		"KAFKA":                 "broker",
		"[FE80::A]":             "[fe80::a]",
	} {
		if got, ok := r.Name(host); !ok || got != want {
			t.Errorf("Name(%q) = %q, %t, want %q, true", host, got, ok, want)
		}
	}
}

// TestReceiversNameRefusesNonASCII gives no name to a host holding a byte outside ASCII, mapped or not,
// whatever Unicode would fold it to: the Kelvin sign is not the letter K.
func TestReceiversNameRefusesNonASCII(t *testing.T) {
	r, err := paztporthttp.NewReceivers(map[string]string{"kafka": "broker"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"\u212Aafka", "\u212Aafka:9092", "caf\u00e9", "[\u212A::1]", "pay\xff", "\u00c9"} {
		if got, ok := r.Name(host); ok || got != "" {
			t.Errorf("Name(%q) = %q, %t, want no name", host, got, ok)
		}
	}
}

// TestNewReceiversRefuses refuses a blank host or name, two hosts differing only in case, a host Name
// could never match (one with a port, an unbracketed colon or a byte outside ASCII), and a name that is
// not a service's: one that is not a route node, or that holds '#' and so names an operation. It names
// the problem but never the host or the name.
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
		{"\u212Aafka": "broker"},
		{"caf\u00e9": "cafe"},
		{"pay.internal": "."},
		{"pay.internal": ".."},
		{"pay.internal": "payment/x"},
		{"pay.internal": `payment\x`},
		{"pay.internal": "payment|x"},
		{"pay.internal": "pay\xffment"},
		{"pay.internal": "payment#pay"},
	} {
		r, err := paztporthttp.NewReceivers(m)
		if err == nil {
			t.Errorf("NewReceivers(%q) = %v", m, r)
			continue
		}
		for host, name := range m {
			if strings.TrimSpace(host) != "" && strings.Contains(err.Error(), host) {
				t.Errorf("the error %q echoes the host", err)
			}
			if len(name) > 2 && strings.Contains(err.Error(), name) {
				t.Errorf("the error %q echoes the name", err)
			}
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
	if got, _ := r.Name("pay.internal"); got != "payment" {
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
// chain that acts on no extension: exactly X-Path-Chain, holding the one origin stamp, then X-Path-Proof, then
// X-Path-Extensions, holding its one empty block, and no X-Path-Proof for a route the bundle holds no proof for.
func TestCallerExtProcOrigin(t *testing.T) {
	caller, pub, proof := originCaller(t)
	body := []byte(`{"qty":1}`)
	o, err := caller.Stamp("POST", "/orders/7?x=%2F", "orders", body, paztporthttp.Inbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := wire.EncodeBlocks(stamp.Blocks{stamp.EmptyBlock})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Headers) != 3 || o.Headers[0].Name != wire.Chain || o.Headers[1].Name != wire.Proof ||
		o.Headers[2] != (wire.Header{Name: wire.Extensions, Value: empty}) {
		t.Fatalf("Headers = %+v, want exactly X-Path-Chain, X-Path-Proof, then the one empty block", o.Headers)
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
		s.Rcv != "orders" || s.Bind != bind || s.Ext != "" || s.Prev != "" {
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
	if rcv := o.Sent[len(o.Sent)-1].Rcv; o.Headers[1].Value != wantProof || o.Proof == nil || rcv != "orders" {
		t.Fatalf("the proof header %q, Proof %v, receiver %q", o.Headers[1].Value, o.Proof, rcv)
	}

	o, err = caller.Stamp("GET", "/statements", "ledger", nil, paztporthttp.Inbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Headers) != 2 || o.Headers[0].Name != wire.Chain || o.Headers[1].Name != wire.Extensions ||
		o.Proof != nil {
		t.Fatalf("with no proof for the route: Headers = %+v, Proof %v", o.Headers, o.Proof)
	}
}

// TestCallerStampBindsTheTarget binds the target as Bind does, a bare trailing "?" left out, and refuses
// a target or method with no UTF-8 form, which gives no binding.
func TestCallerStampBindsTheTarget(t *testing.T) {
	caller, _, _ := originCaller(t)
	o, err := caller.Stamp("GET", "/pay?", "orders", nil, paztporthttp.Inbound{}, nil)
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
	for _, tc := range []struct{ method, target string }{
		{"GET", "/p\xff"},
		{"GET", "/p\xed\xa0\x80"},
		{"G\xffT", "/p"},
		{"", "/p"},
		{"GET", ""},
	} {
		o, err := caller.Stamp(tc.method, tc.target, "orders", nil, paztporthttp.Inbound{}, nil)
		if err == nil {
			t.Errorf("Stamp(%q, %q) = %+v, want an error", tc.method, tc.target, o)
		}
		if o.Headers != nil || o.Sent != nil {
			t.Errorf("Stamp(%q, %q) with an error gave %+v", tc.method, tc.target, o)
		}
	}
}

// TestCallerStampLeavesItsInputs never writes into the inbound chain's, its blocks' or what was added's backing
// arrays, even where they have room.
func TestCallerStampLeavesItsInputs(t *testing.T) {
	c := callerCase(t, "each label becomes an entry")
	chain, blocks := chainOf(c.Get("inbound")), blocksOf(t, c.Get("inboundBlocks"))
	inbound := paztporthttp.Inbound{
		Chain:  append(make(stamp.Chain, 0, len(chain)+1), chain...),
		Blocks: append(make(stamp.Blocks, 0, len(blocks)+1), blocks...),
	}
	added := entries(c.Get("added"))
	spare := append(make([]influence.Entry, 0, len(added)+1), added...)
	signed := 0
	caller := hopCaller(t, actsOnInfluence(t), &signed)
	o, err := caller.Stamp("POST", "/pay", "payment", nil, inbound, spare)
	if err != nil {
		t.Fatal(err)
	}
	if inbound.Chain[:cap(inbound.Chain)][len(chain)] != (stamp.Stamp{}) ||
		inbound.Blocks[:cap(inbound.Blocks)][len(blocks)].Commit() != "" ||
		spare[:cap(spare)][len(spare)] != (influence.Entry{}) {
		t.Fatal("Stamp wrote past the end of a slice it was given")
	}
	if !slices.Equal(inbound.Chain, chain) || !slices.Equal(spare, added) || len(o.Sent) != len(chain)+1 ||
		len(o.Blocks) != len(chain)+1 {
		t.Fatalf("Stamp changed its inputs, or sent %d stamps and %d blocks", len(o.Sent), len(o.Blocks))
	}
}

// hopCaller returns orders' caller, a hop that is no origin, with settings ext and no verifier; its stamper
// counts in signed each stamp it signs.
func hopCaller(t *testing.T, ext verify.Extensions, signed *int) *paztporthttp.Caller {
	t.Helper()
	priv, _ := vectors.RulesKey(t, "orders")
	return &paztporthttp.Caller{
		Stamper: &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: priv, Now: func() int64 {
			*signed++
			return 1767225599500
		}},
		Extensions: ext,
	}
}

// actsOnInfluence returns settings that act on influence and carry any name.
func actsOnInfluence(t testing.TB) verify.Extensions {
	t.Helper()
	ext, err := verify.NewExtensions([]string{influence.Name})
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

// forwarded returns the inbound of the callerInfluence case "each label becomes an entry": gateway's one stamp
// and its block, which names influence with nothing.
func forwarded(t *testing.T) paztporthttp.Inbound {
	t.Helper()
	c := callerCase(t, "each label becomes an entry")
	return paztporthttp.Inbound{Chain: chainOf(c.Get("inbound")), Blocks: blocksOf(t, c.Get("inboundBlocks"))}
}

// sentBlocks returns the blocks o's X-Path-Extensions header holds, failing t unless they are o.Blocks and one
// per stamp sent, the last the one its own stamp commits to.
func sentBlocks(t *testing.T, o paztporthttp.Outbound) stamp.Blocks {
	t.Helper()
	var tok string
	for _, h := range o.Headers {
		if h.Name == wire.Extensions {
			tok = h.Value
		}
	}
	bs, err := stamp.ReadBlocks(tok)
	if err != nil {
		t.Fatalf("the blocks header %q does not read: %v", tok, err)
	}
	want, err := o.Blocks.Token()
	if err != nil || tok != want || len(bs) != len(o.Sent) {
		t.Fatalf("the blocks header holds %d blocks for %d stamps, Blocks %+v", len(bs), len(o.Sent), o.Blocks)
	}
	if last := o.Sent[len(o.Sent)-1]; last.Ext != bs[len(bs)-1].Commit() {
		t.Fatalf("the call's stamp commits to %q, its block to %q", last.Ext, bs[len(bs)-1].Commit())
	}
	return bs
}

// TestEveryCallCarriesTheBlocksHeader sends X-Path-Extensions with every call: an origin's, which acts on no
// extension, holds its one empty block; a forwarded call holds the blocks received, unchanged, then the caller's
// own; and a call after a chain received with no blocks holds one empty block for each stamp received.
func TestEveryCallCarriesTheBlocksHeader(t *testing.T) {
	origin, _, _ := originCaller(t)
	o, err := origin.Stamp("GET", "/orders/7", "orders", nil, paztporthttp.Inbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bs := sentBlocks(t, o); len(bs) != 1 || bs[0].Commit() != "" {
		t.Fatalf("an origin's call sends %+v, want the one empty block", bs)
	}

	signed := 0
	in := forwarded(t)
	o, err = hopCaller(t, verify.Extensions{}, &signed).Stamp("POST", "/pay", "payment", nil, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	bs := sentBlocks(t, o)
	if len(bs) != 2 || bs[0].Commit() != in.Blocks[0].Commit() || in.Blocks[0].Commit() == "" ||
		bs[1].Commit() != "" {
		t.Fatalf("a forwarded call sends %+v, want the block received then the empty block", bs)
	}

	in.Blocks = nil
	o, err = hopCaller(t, verify.Extensions{}, &signed).Stamp("POST", "/pay", "payment", nil, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bs := sentBlocks(t, o); len(bs) != 2 || bs[0].Commit() != "" || bs[1].Commit() != "" {
		t.Fatalf("a call after no blocks sends %+v, want an empty block for each stamp", bs)
	}
}

// TestAHopActingOnInfluenceSignsWhatItAdded signs, at a hop whose settings act on influence, its own block naming
// influence with what it added, [] when it added nothing, and requiring what it requires of the receiver.
func TestAHopActingOnInfluenceSignsWhatItAdded(t *testing.T) {
	added := entries(callerCase(t, "each label becomes an entry").Get("added"))
	for name, tc := range map[string]struct {
		added    []influence.Entry
		requires []string
	}{
		"what it added":        {added, nil},
		"nothing added":        {nil, nil},
		"requiring influence":  {added, []string{influence.Name}},
		"a requirement of one": {nil, []string{"example"}},
	} {
		t.Run(name, func(t *testing.T) {
			signed := 0
			caller := hopCaller(t, actsOnInfluence(t), &signed)
			caller.Requires = map[string][]string{"payment": tc.requires, "ledger": {"other"}}
			o, err := caller.Stamp("POST", "/pay", "payment#pay", nil, forwarded(t), tc.added)
			if err != nil {
				t.Fatal(err)
			}
			want, err := influence.RequestBlock(tc.added, tc.requires)
			if err != nil {
				t.Fatal(err)
			}
			bs := sentBlocks(t, o)
			if got := bs[len(bs)-1]; got.Commit() != want.Commit() {
				t.Fatalf("the call signs %s, want %s", got.Wire(), want.Wire())
			}
			if items, named := bs[len(bs)-1].Items(influence.Name); !named || len(items) != len(tc.added) {
				t.Fatalf("the call's block names influence %v with %d items, want %d", named, len(items),
					len(tc.added))
			}
		})
	}
}

// TestAHopNotActingOnInfluenceSignsTheEmptyBlockOrOnlyRequires signs, at a hop whose settings do not act on
// influence, a block that names nothing, whatever it added: the empty block, or one that only requires what the
// hop requires of the receiver.
func TestAHopNotActingOnInfluenceSignsTheEmptyBlockOrOnlyRequires(t *testing.T) {
	added := entries(callerCase(t, "each label becomes an entry").Get("added"))
	signed := 0
	caller := hopCaller(t, verify.Extensions{}, &signed)
	o, err := caller.Stamp("POST", "/pay", "payment", nil, forwarded(t), added)
	if err != nil {
		t.Fatal(err)
	}
	if bs := sentBlocks(t, o); bs[len(bs)-1].Commit() != "" {
		t.Fatalf("the call signs %s, want the empty block", bs[len(bs)-1].Wire())
	}
	caller.Requires = map[string][]string{"payment": {influence.Name}}
	o, err = caller.Stamp("POST", "/pay", "payment", nil, forwarded(t), added)
	if err != nil {
		t.Fatal(err)
	}
	last := sentBlocks(t, o)[len(o.Sent)-1]
	if string(last.Wire()) != `{"items":{},"requires":["influence"]}` {
		t.Fatalf("the call signs %s, want a block that only requires influence", last.Wire())
	}
}

// wantNothingSigned fails t unless Stamp refused with an error, gave the zero Outbound and signed nothing.
func wantNothingSigned(t *testing.T, o paztporthttp.Outbound, err error, signed int) {
	t.Helper()
	if err == nil {
		t.Fatalf("Stamp = %+v, want an error", o)
	}
	if signed != 0 || o.Headers != nil || o.Sent != nil || o.Blocks != nil {
		t.Fatalf("signed %d stamps, Outbound %+v; want nothing", signed, o)
	}
	if !strings.HasSuffix(err.Error(), "nothing is sent") && !strings.Contains(err.Error(), "nothing is sent:") {
		t.Errorf("the error %q does not say nothing is sent", err)
	}
}

// TestInboundBlocksNotOnePerStampAreRefused signs nothing for inbound blocks of another length than its chain,
// which the next hop would refuse at check 9a; nil blocks are one empty block per stamp.
func TestInboundBlocksNotOnePerStampAreRefused(t *testing.T) {
	in := forwarded(t)
	for name, blocks := range map[string]stamp.Blocks{
		"none":      {},
		"two":       {stamp.EmptyBlock, stamp.EmptyBlock},
		"one short": in.Blocks[:0],
	} {
		signed := 0
		bad := paztporthttp.Inbound{Chain: in.Chain, Blocks: blocks}
		o, err := hopCaller(t, actsOnInfluence(t), &signed).Stamp("POST", "/pay", "payment", nil, bad, nil)
		t.Run(name, func(t *testing.T) { wantNothingSigned(t, o, err, signed) })
	}
}

// TestBlocksBesideNoChainAreRefused signs nothing for inbound blocks with no chain, an empty list of them
// included, at a hop and at an origin alike.
func TestBlocksBesideNoChainAreRefused(t *testing.T) {
	for name, blocks := range map[string]stamp.Blocks{"one": {stamp.EmptyBlock}, "an empty list": {}} {
		t.Run(name, func(t *testing.T) {
			signed := 0
			bad := paztporthttp.Inbound{Blocks: blocks}
			o, err := hopCaller(t, actsOnInfluence(t), &signed).Stamp("POST", "/pay", "payment", nil, bad, nil)
			wantNothingSigned(t, o, err, signed)
			origin, _, _ := originCaller(t)
			origin.Stamper.Now = func() int64 {
				signed++
				return 1767225600000
			}
			o, err = origin.Stamp("POST", "/orders", "orders", nil, bad, nil)
			wantNothingSigned(t, o, err, signed)
		})
	}
}

// bigEntries returns n entries of about 1 KB each.
func bigEntries(n int) []influence.Entry {
	es := make([]influence.Entry, n)
	for i := range es {
		es[i] = influence.Entry{Class: influence.Public, Src: "http:catalogue", H: strings.Repeat("h", 1000)}
	}
	return es
}

// TestBlocksPastTheWireLimitAreRefusedBeforeSigning refuses a call whose blocks header would pass the wire limit,
// 256 KiB, before anything is signed: nothing is dropped to make room. Each block here is under the limit, the
// one received and the caller's own alike; only the header holding both passes it, so the call is refused only
// because the header is written before the stamp is signed.
func TestBlocksPastTheWireLimitAreRefusedBeforeSigning(t *testing.T) {
	received, err := influence.RequestBlock(bigEntries(200), nil)
	if err != nil {
		t.Fatalf("the block received is past the limit alone: %v", err)
	}
	if _, err := influence.RequestBlock(bigEntries(100), nil); err != nil {
		t.Fatalf("the caller's own block is past the limit alone: %v", err)
	}
	in := forwarded(t)
	in.Blocks = stamp.Blocks{received}
	signed := 0
	o, err := hopCaller(t, actsOnInfluence(t), &signed).Stamp("POST", "/pay", "payment", nil, in, bigEntries(100))
	wantNothingSigned(t, o, err, signed)
	// With the empty block received, the same call is under the limit, and signed.
	if _, err := hopCaller(t, actsOnInfluence(t), &signed).Stamp("POST", "/pay", "payment", nil, forwarded(t),
		bigEntries(100)); err != nil || signed != 1 {
		t.Fatalf("a call under the limit: %v, signed %d", err, signed)
	}
}

// TestAnOwnBlockPastTheWireLimitIsRefusedBeforeSigning refuses a call whose own block alone would pass the wire
// limit, signing nothing.
func TestAnOwnBlockPastTheWireLimitIsRefusedBeforeSigning(t *testing.T) {
	signed := 0
	o, err := hopCaller(t, actsOnInfluence(t), &signed).Stamp("POST", "/pay", "payment", nil, forwarded(t),
		bigEntries(300))
	wantNothingSigned(t, o, err, signed)
}

// TestARequiresNameThatIsNotAnExtensionNameIsRefused signs nothing for a call to a receiver whose requirement
// holds a name that is not an extension name, or one name twice, and calls to other receivers are signed.
func TestARequiresNameThatIsNotAnExtensionNameIsRefused(t *testing.T) {
	for _, ext := range []verify.Extensions{{}, actsOnInfluence(t)} {
		for _, requires := range [][]string{{"Influence"}, {""}, {"influence", "influence"}} {
			signed := 0
			caller := hopCaller(t, ext, &signed)
			caller.Requires = map[string][]string{"payment": requires}
			o, err := caller.Stamp("POST", "/pay", "payment#pay", nil, forwarded(t), nil)
			wantNothingSigned(t, o, err, signed)
			if _, err := caller.Stamp("POST", "/charge", "ledger", nil, forwarded(t), nil); err != nil {
				t.Fatalf("a call to another receiver: %v", err)
			}
		}
	}
}

// TestCallerSettingsBesideAVerifierWithOthersPanic: a caller states its settings once, so settings beside a
// verifier that hold others panic, a fault in the program; the zero settings and the verifier's own do not.
func TestCallerSettingsBesideAVerifierWithOthersPanic(t *testing.T) {
	c := callerCase(t, "each label becomes an entry")
	carriesNothing, err := verify.NewExtensionsAllowing(nil, []string{})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		given  verify.Extensions
		panics bool
	}{
		"the verifier's own": {caseSettings(t, c), false},
		"the zero settings":  {verify.Extensions{}, false},
		"others":             {carriesNothing, true},
	} {
		t.Run(name, func(t *testing.T) {
			caller, _ := stampCallerCase(t, c, nil)
			caller.Extensions = tc.given
			defer func() {
				if got := recover() != nil; got != tc.panics {
					t.Fatalf("panicked %v, want %v", got, tc.panics)
				}
			}()
			o, err := caller.Stamp("POST", "/pay", "payment", nil, forwarded(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			if last := o.Blocks[len(o.Blocks)-1]; !slices.Contains(last.Names(), influence.Name) {
				t.Fatalf("the call signs %s, want the verifier's settings to name influence", last.Wire())
			}
		})
	}
}

// TestACallerWithNoVerifierAddsOneUntrustedEntry checks nothing, so a response adds one local-untrusted entry from
// the receiver, by its result hash, though its header holds labels an acting responder signed, and it is never
// refused, whatever the caller's settings: a label counts only when the whole response verifies.
func TestACallerWithNoVerifierAddsOneUntrustedEntry(t *testing.T) {
	c := verifiedCase(t)
	a := accept(t, c, caseRequest(t, c.Get("request")), paztporthttp.ModeEnforce)
	wantServed(t, a, true)
	o := sentTo(t, c, a)
	body := []byte(`{"receipt":"r-1"}`)
	h, ok, err := a.Attest(200, body, answerLabels)
	if err != nil || !ok {
		t.Fatalf("Attest = %q, %v, %v", h, ok, err)
	}
	settings := map[string]verify.Extensions{"acting on influence": actsOnInfluence(t), "acting on nothing": {}}
	for name, ext := range settings {
		caller := &paztporthttp.Caller{Stamper: &stamp.Stamper{Svc: "orders"}, Extensions: ext}
		got, err := caller.Check(t.Context(), o, h, 200, body)
		if err != nil {
			t.Fatal(err)
		}
		if want := untrustedFrom(200, body); got.Check != nil || !slices.Equal(got.Entries, want) || got.Refused {
			t.Fatalf("%s: Check = %+v, want no check, %+v and not refused", name, got, want)
		}
	}
}
