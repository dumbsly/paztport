// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package vectors

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"testing"
)

// TestRulesKey finds a key in the rules' own keys, then in http-v3.json's, then in v3.json's, and fails
// the test for a key none lists.
func TestRulesKey(t *testing.T) {
	for _, name := range []string{"shop-policy", "psp", "shop-ca", "payment", "gateway"} {
		priv, pub := RulesKey(t, name)
		if !ed25519.Verify(pub, []byte(name), ed25519.Sign(priv, []byte(name))) {
			t.Errorf("RulesKey(%q) gives a public key that is not the private key's", name)
		}
		if want, _, _, _ := derivedKey(name); !priv.Equal(want) {
			t.Errorf("RulesKey(%q) is not the key v3.json's rule derives", name)
		}
	}
	if msg := failure(t, func(tb testing.TB) { RulesKey(tb, "nobody") }); msg == "" {
		t.Fatal("RulesKey of a key no file lists did not fail the test")
	}
}

// TestRulesMaterial hands over each file as its exact text, the proofs in file order, and a partner's
// entry and reply certificate.
func TestRulesMaterial(t *testing.T) {
	shop := RulesMaterial(t, "shop")
	if shop.PolicyKey != "shop-policy" || shop.Entry != "" || shop.ReplyCert != nil {
		t.Fatalf("shop = %q, entry %q, reply certificate %q", shop.PolicyKey, shop.Entry, shop.ReplyCert)
	}
	m := Rules(t).Get("material").Get("shop")
	if !bytes.Equal(shop.Root, m.Get("root").Raw()) || !bytes.Equal(shop.Keyring, m.Get("keyring").Raw()) {
		t.Fatal("shop's root or keyring is not its text in the file")
	}
	var routes []string
	for _, p := range shop.Proofs {
		routes = append(routes, p.Route)
		if !bytes.Equal(p.Text, m.Get("proofs").Get(p.Route).Raw()) {
			t.Fatalf("the proof of %s is not its text in the file", p.Route)
		}
	}
	if want := []string{"gateway/orders/payment", "payment/psp"}; !slices.Equal(routes, want) {
		t.Fatalf("shop's proofs are of %q, want %q", routes, want)
	}

	psp := RulesMaterial(t, "psp")
	if psp.Entry != "psp" || !bytes.HasPrefix(psp.ReplyCert, []byte("{")) {
		t.Fatalf("psp's entry %q, reply certificate %q", psp.Entry, psp.ReplyCert)
	}
}

// TestRulesPeerAndHandshake decodes a client certificate's DER and a handshake's body from hex.
func TestRulesPeerAndHandshake(t *testing.T) {
	der, addr := RulesPeer(t, "shop")
	if len(der) == 0 || der[0] != 0x30 || addr == "" {
		t.Fatalf("the shop peer: DER % x..., address %q", der[:min(4, len(der))], addr)
	}
	if body := RulesHandshakeBody(t, "shop"); !bytes.HasPrefix(body, []byte(`{"clientKeyring":`)) {
		t.Fatalf("the shop handshake's body starts %q", body[:min(20, len(body))])
	}
}
