// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"context"
	"crypto/ed25519"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// The keyed-operation tests build their own one-route policies: a tree of one leaf is its own root, so
// the proof of a route holds no siblings.

const (
	keyedNow      = 10_000
	keyedNotAfter = 1 << 40
)

// ordersKeyed is orders' own table: reserve is keyed by the item in its path, createOrder has no key.
func ordersKeyed(t testing.TB) policy.OperationTable {
	t.Helper()
	table, err := policy.ReadOperationTable([]byte(`{"operations":[` +
		`{"key":{"segment":1},"method":"POST","name":"reserve","template":"/items/{}/reserve"},` +
		`{"method":"POST","name":"createOrder","template":"/orders"}],"service":"orders","v":1}`))
	if err != nil {
		t.Fatalf("ReadOperationTable: %v", err)
	}
	return table
}

// recordingNonces is a nonce cache that remembers, in order, every key it is asked about.
type recordingNonces struct {
	mu    sync.Mutex
	asked []string
	cache verify.NonceCache
}

func newRecordingNonces() *recordingNonces {
	return &recordingNonces{cache: verify.NewMemoryNonceCache(verify.NonceTTLMs)}
}

func (r *recordingNonces) SeenBefore(ctx context.Context, key string, now int64) (bool, error) {
	r.mu.Lock()
	r.asked = append(r.asked, key)
	r.mu.Unlock()
	return r.cache.SeenBefore(ctx, key, now)
}

func (r *recordingNonces) TTL() int64 { return r.cache.TTL() }

// keyedPolicy is a policy of one-leaf trees, one for each route, signed by nobody: its roots are pinned
// directly.
type keyedPolicy struct {
	gw, ord ed25519.PrivateKey
	roots   []verify.PinnedRoot
	bundle  policy.ProofBundle
}

func newKeyedPolicy(t testing.TB, routes ...string) keyedPolicy {
	t.Helper()
	gw, _ := keyPair(t, "gateway")
	ord, _ := keyPair(t, "orders")
	p := keyedPolicy{gw: gw, ord: ord, bundle: policy.ProofBundle{
		Service: "gateway", RootID: "r0", Proofs: map[string]policy.Proof{}}}
	for i, route := range routes {
		id := "r" + string(rune('0'+i))
		salt := []byte("0123456789abcde" + string(rune('0'+i)))
		root, err := policy.LeafHash(salt, route)
		if err != nil {
			t.Fatalf("LeafHash: %v", err)
		}
		p.roots = append(p.roots, verify.PinnedRoot{Root: root, RootID: id, NotAfter: keyedNotAfter})
		p.bundle.Proofs[route] = policy.Proof{LeafSalt: salt, RootID: id}
	}
	return p
}

// verifier returns a verifier at now keyedNow pinned to the policy, over nonces, for services' keys.
func (p keyedPolicy) verifier(t testing.TB, nonces verify.NonceCache, services ...string) *verify.Verifier {
	t.Helper()
	ring := policy.Keyring{}
	for _, svc := range services {
		_, ring[svc] = keyPair(t, svc)
	}
	return verify.New(verify.Config{
		Keyrings:       []verify.PinnedKeyring{{Keys: ring, NotAfter: keyedNotAfter}},
		Roots:          p.roots,
		PolicyNotAfter: keyedNotAfter,
		AllowedOrigins: []string{"gateway"},
		Nonces:         nonces,
		Now:            func() int64 { return keyedNow },
		CallMaxAgeMs:   5000,
		RunMaxAgeMs:    5000,
	})
}

// keyPair returns the key of service svc, derived from its name so that a test can ask again.
func keyPair(t testing.TB, svc string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "keyed-test:"+svc)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// toOrders returns the request gateway sends orders: POST target, its stamp addressed to named, in the
// request tree rid.
func (p keyedPolicy) toOrders(t testing.TB, rid, named, target string) paztporthttp.InboundRequest {
	t.Helper()
	gw := &stamp.Stamper{Svc: "gateway", Inst: "gw-1", Key: p.gw, Origin: true,
		NewRID: func() string { return rid }, Now: func() int64 { return keyedNow - 500 }}
	bind, err := wire.Bind("POST", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, proof, err := gw.Next(nil, named, bind, nil, p.bundle)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	chainTok, err := wire.EncodeChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	proofTok, err := wire.EncodeProof(*proof)
	if err != nil {
		t.Fatal(err)
	}
	return paztporthttp.InboundRequest{Method: "POST", Target: target, Chain: chainTok, Proof: proofTok}
}

// ordersReceiver is orders, verifying requests under p, holding its own keyed table, naming the request
// name; it is the embedder's, which chooses it from its own routing.
func (p keyedPolicy) ordersReceiver(t testing.TB, name string, nonces verify.NonceCache) *paztporthttp.Receiver {
	t.Helper()
	table := ordersKeyed(t)
	return &paztporthttp.Receiver{
		Name:       name,
		Verifier:   p.verifier(t, nonces, "gateway"),
		Operations: &table,
		Stamper: &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: p.ord,
			Now: func() int64 { return keyedNow }},
	}
}

func wantRefusal(t *testing.T, a paztporthttp.Accepted, code reason.Code) {
	t.Helper()
	if a.Refusal == nil || a.Refusal.Status != 403 || string(a.Refusal.Body) != `{"reason":"`+string(code)+`"}` {
		t.Fatalf("Refusal = %+v, want 403 %s", a.Refusal, code)
	}
}

// TestKeyedOperationSpendsItsItemKey spends <rid>|<svc>|<rcv>|<key>|req for a request to a keyed
// operation.
func TestKeyedOperationSpendsItsItemKey(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	nonces := newRecordingNonces()
	r := p.ordersReceiver(t, "orders#reserve", nonces)
	a := r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders#reserve", "/items/A1/reserve"), nil,
		paztporthttp.ModeEnforce)
	if a.Refusal != nil || !a.Verified {
		t.Fatalf("Accept = refusal %+v, verified %v", a.Refusal, a.Verified)
	}
	if want := []string{"rid-1|gateway|orders#reserve|A1|req"}; !slices.Equal(nonces.asked, want) {
		t.Fatalf("nonce keys %q, want %q", nonces.asked, want)
	}
}

// TestKeyedTwoItemsBothServed serves two items of one request tree.
func TestKeyedTwoItemsBothServed(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	nonces := newRecordingNonces()
	r := p.ordersReceiver(t, "orders#reserve", nonces)
	for _, item := range []string{"A1", "B2"} {
		a := r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders#reserve", "/items/"+item+"/reserve"), nil,
			paztporthttp.ModeEnforce)
		if a.Refusal != nil {
			t.Fatalf("item %s: Refusal = %+v", item, a.Refusal)
		}
	}
}

// TestKeyedOneItemTwiceIsReplay refuses the same item of one request tree the second time.
func TestKeyedOneItemTwiceIsReplay(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	r := p.ordersReceiver(t, "orders#reserve", newRecordingNonces())
	req := p.toOrders(t, "rid-1", "orders#reserve", "/items/A1/reserve")
	if a := r.Accept(t.Context(), req, nil, paztporthttp.ModeEnforce); a.Refusal != nil {
		t.Fatalf("first: Refusal = %+v", a.Refusal)
	}
	wantRefusal(t, r.Accept(t.Context(), req, nil, paztporthttp.ModeEnforce), reason.Replay)
}

// TestKeyedNoKeyValueIsBindingMismatch verifies a keyed operation with no key value under the service
// alone, which the chain naming the operation fails, with nothing spent.
func TestKeyedNoKeyValueIsBindingMismatch(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	nonces := newRecordingNonces()
	r := p.ordersReceiver(t, "orders#reserve", nonces)
	a := r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders#reserve", "/items/%41/reserve"), nil,
		paztporthttp.ModeEnforce)
	wantRefusal(t, a, reason.BindingMismatch)
	if len(nonces.asked) != 0 {
		t.Fatalf("nonce keys %q were spent, want none", nonces.asked)
	}
}

// TestKeyedNoKeyValueUnderAuditIsNotVerified serves it, unverified, with no delivery.
func TestKeyedNoKeyValueUnderAuditIsNotVerified(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	r := p.ordersReceiver(t, "orders#reserve", newRecordingNonces())
	a := r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders#reserve", "/items/%41/reserve"), nil,
		paztporthttp.ModeAudit)
	if a.Refusal != nil || a.Verified || a.Result == nil || a.Result.Reason != reason.BindingMismatch {
		t.Fatalf("Accept = refusal %+v, verified %v, result %+v", a.Refusal, a.Verified, a.Result)
	}
	if d, ok := a.Delivery(); ok {
		t.Fatalf("Delivery = %+v, want none", d)
	}
}

// TestKeyedBareChainSpendsBareKey reads no key value for a chain naming no operation: the embedder, whose
// routing ran the keyed operation, names the service alone, and the bare key is spent. Were it to name the
// operation anyway, the chain would fail check 4 before any key was spent.
func TestKeyedBareChainSpendsBareKey(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders")
	nonces := newRecordingNonces()
	r := p.ordersReceiver(t, "orders", nonces)
	a := r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders", "/items/A1/reserve"), nil, paztporthttp.ModeEnforce)
	if a.Refusal != nil {
		t.Fatalf("Refusal = %+v", a.Refusal)
	}
	if want := []string{"rid-1|gateway|orders|req"}; !slices.Equal(nonces.asked, want) {
		t.Fatalf("nonce keys %q, want %q", nonces.asked, want)
	}
	if d, ok := a.Delivery(); !ok || d.Key != "" {
		t.Fatalf("Delivery = %+v, %v, want one with no key", d, ok)
	}

	nonces = newRecordingNonces()
	r = p.ordersReceiver(t, "orders#reserve", nonces)
	a = r.Accept(t.Context(), p.toOrders(t, "rid-1", "orders", "/items/A1/reserve"), nil, paztporthttp.ModeEnforce)
	wantRefusal(t, a, reason.BindingMismatch)
	if len(nonces.asked) != 0 {
		t.Fatalf("nonce keys %q were spent, want none", nonces.asked)
	}
}

// TestKeyedDeliveryCarriesKey names the key value in the delivery of a keyed operation, and none in the
// delivery of one with no key.
func TestKeyedDeliveryCarriesKey(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve", "gateway/orders#createOrder")
	keyed := p.ordersReceiver(t, "orders#reserve", newRecordingNonces()).Accept(t.Context(),
		p.toOrders(t, "rid-1", "orders#reserve", "/items/A1/reserve"), nil, paztporthttp.ModeEnforce)
	unkeyed := p.ordersReceiver(t, "orders#createOrder", newRecordingNonces()).Accept(t.Context(),
		p.toOrders(t, "rid-1", "orders#createOrder", "/orders"), nil, paztporthttp.ModeEnforce)

	bind, err := wire.Bind("POST", "/items/A1/reserve", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := paztporthttp.Delivery{RID: "rid-1", Svc: "gateway", Rcv: "orders#reserve", Key: "A1", Bind: bind}
	if d, ok := keyed.Delivery(); !ok || d != want {
		t.Fatalf("Delivery = %+v, %v, want %+v", d, ok, want)
	}
	if d, ok := unkeyed.Delivery(); !ok || d.Rcv != "orders#createOrder" || d.Key != "" {
		t.Fatalf("Delivery = %+v, %v, want createOrder with no key", d, ok)
	}
}

// TestKeyedATableForAnotherServicePanics treats a table that is not the receiver's own as a fault in the
// program.
func TestKeyedATableForAnotherServicePanics(t *testing.T) {
	table := ordersKeyed(t)
	r := &paztporthttp.Receiver{Name: "payment#pay", Operations: &table}
	defer func() {
		v := recover()
		msg, _ := v.(string)
		if !strings.Contains(msg, "orders") || !strings.Contains(msg, "payment") {
			t.Fatalf("Accept panicked with %v, want a message naming both services", v)
		}
	}()
	r.Accept(t.Context(), paztporthttp.InboundRequest{Method: "POST", Target: "/pay"}, nil, paztporthttp.ModeOff)
	t.Fatal("Accept did not panic")
}

// callerFor returns gateway's caller under p, holding tables, checking responses over nonces; its stamper
// counts what it signs in signed.
func (p keyedPolicy) callerFor(
	t testing.TB, nonces verify.NonceCache, signed *int, tables ...policy.OperationTable,
) *paztporthttp.Caller {
	t.Helper()
	c := &paztporthttp.Caller{
		Stamper: &stamp.Stamper{Svc: "gateway", Inst: "gw-1", Key: p.gw, Origin: true,
			NewRID: func() string { return "rid-1" },
			Now: func() int64 {
				*signed++
				return keyedNow - 500
			}},
		Bundle:   p.bundle,
		Verifier: p.verifier(t, nonces, "gateway", "orders"),
	}
	if len(tables) > 0 {
		c.Operations = map[string]policy.OperationTable{}
		for _, table := range tables {
			c.Operations[table.Service] = table
		}
	}
	return c
}

// attested returns orders' X-Path-Response header for the answer 200 "held" to the call o.
func (p keyedPolicy) attested(t testing.TB, o paztporthttp.Outbound) string {
	t.Helper()
	ord := &stamp.Stamper{Svc: "orders", Inst: "ord-1", Key: p.ord, Now: func() int64 { return keyedNow }}
	hash := wire.ResultHash(200, []byte("held"))
	s, err := ord.Respond(o.Sent, hash, o.Sent[0].RID, nil)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	h, err := wire.EncodeResponse(s, []influence.Label(nil))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestCallerKeyedCallCarriesKey names the keyed operation the call matches, keeps its key value in
// Outbound.Key and spends it in the response's nonce key.
func TestCallerKeyedCallCarriesKey(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	nonces, signed := newRecordingNonces(), 0
	c := p.callerFor(t, nonces, &signed, ordersKeyed(t))
	o, err := c.Stamp("POST", "/items/A1/reserve", "orders", nil, nil, nil)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if o.Key != "A1" || o.Sent[0].Rcv != "orders#reserve" {
		t.Fatalf("Key %q, rcv %q, want A1 and orders#reserve", o.Key, o.Sent[0].Rcv)
	}
	got, err := c.Check(t.Context(), o, p.attested(t, o), 200, []byte("held"))
	if err != nil || got.Check == nil || !got.Check.Result.OK() {
		t.Fatalf("Check = %+v, %v, want OK", got, err)
	}
	if want := []string{"rid-1|orders#reserve|A1|resp"}; !slices.Equal(nonces.asked, want) {
		t.Fatalf("nonce keys %q, want %q", nonces.asked, want)
	}
}

// TestCallerKeyedCallWithoutValueIsRefused signs nothing for a keyed operation that gives no key value, and
// its error names neither the target nor the value.
func TestCallerKeyedCallWithoutValueIsRefused(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#reserve")
	signed := 0
	c := p.callerFor(t, newRecordingNonces(), &signed, ordersKeyed(t))
	o, err := c.Stamp("POST", "/items/%41/reserve", "orders", nil, nil, nil)
	if err == nil {
		t.Fatalf("Stamp = %+v, want an error", o)
	}
	if signed != 0 || o.Headers != nil || o.Sent != nil {
		t.Fatalf("signed %d times, Outbound %+v; want nothing", signed, o)
	}
	for _, leak := range []string{"/items", "%41"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error %q names %q", err, leak)
		}
	}
	if !strings.Contains(err.Error(), "orders#reserve") || !strings.HasSuffix(err.Error(), "; nothing is sent") {
		t.Errorf("the error %q does not name the receiver and operation, or end with the usual words", err)
	}
}

// TestCallerBareCallerKeepsOncePerTree names the service alone, with no key value, for a caller that holds
// no table for it: the keys are today's.
func TestCallerBareCallerKeepsOncePerTree(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders")
	nonces, signed := newRecordingNonces(), 0
	// A table for another service is not orders'.
	other, err := policy.ReadOperationTable([]byte(
		`{"operations":[{"method":"POST","name":"pay","template":"/pay"}],"service":"payment","v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c := p.callerFor(t, nonces, &signed, other)
	o, err := c.Stamp("POST", "/items/A1/reserve", "orders", nil, nil, nil)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if o.Key != "" || o.Sent[0].Rcv != "orders" {
		t.Fatalf("Key %q, rcv %q, want none and orders", o.Key, o.Sent[0].Rcv)
	}
	got, err := c.Check(t.Context(), o, p.attested(t, o), 200, []byte("held"))
	if err != nil || got.Check == nil || !got.Check.Result.OK() {
		t.Fatalf("Check = %+v, %v, want OK", got, err)
	}
	if want := []string{"rid-1|orders|resp"}; !slices.Equal(nonces.asked, want) {
		t.Fatalf("nonce keys %q, want %q", nonces.asked, want)
	}
}

// TestCallerOperationTableMatching names an unkeyed operation, accepts a receiver naming the operation the
// call matches, and refuses a call no operation matches or a receiver naming another, signing nothing.
func TestCallerOperationTableMatching(t *testing.T) {
	p := newKeyedPolicy(t, "gateway/orders#createOrder")
	signed := 0
	c := p.callerFor(t, newRecordingNonces(), &signed, ordersKeyed(t))
	for _, receiver := range []string{"orders", "orders#createOrder"} {
		o, err := c.Stamp("POST", "/orders", receiver, nil, nil, nil)
		if err != nil || o.Sent[0].Rcv != "orders#createOrder" || o.Key != "" {
			t.Fatalf("Stamp to %s = rcv %v, key %q, %v", receiver, o.Sent, o.Key, err)
		}
	}
	signed = 0
	for _, tc := range []struct{ method, target, receiver string }{
		{"GET", "/orders", "orders"},
		{"POST", "/elsewhere", "orders"},
		{"POST", "/orders", "orders#reserve"},
		{"POST", "/items/A1/reserve", "orders#createOrder"},
	} {
		if o, err := c.Stamp(tc.method, tc.target, tc.receiver, nil, nil, nil); err == nil {
			t.Errorf("Stamp(%s %s to %s) = %+v, want an error", tc.method, tc.target, tc.receiver, o)
		}
	}
	if signed != 0 {
		t.Fatalf("signed %d times, want none", signed)
	}
}
