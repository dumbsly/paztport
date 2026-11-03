// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package vectors

import (
	"crypto/ed25519"
	"testing"
)

// The fixtures http-v3.json's rules section shares between its cases: keys, each organisation's policy
// material, client certificates and handshake bodies. They are handed over as the file holds them, as
// text or bytes, never as SDK values, so that each package's tests read them with the SDK's own readers.

// rulesFile is the vector file holding the rules section.
const rulesFile = "http-v3.json"

// Rules returns http-v3.json's rules section.
func Rules(t testing.TB) Node {
	t.Helper()
	return Load(t, rulesFile).Get("rules")
}

// RulesKey returns the key called name as the rules section finds it: in its own keys, then in
// http-v3.json's keys, then in v3.json's. Every one is derived by v3.json's rule, so it fails the test
// unless the keys listed under name are the ones that rule derives.
func RulesKey(t testing.TB, name string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	keys := Rules(t).Get("keys")
	if !keys.Has(name) {
		return V3Key(t, name)
	}
	priv, pub, wantPriv, wantPub := derivedKey(name)
	key := keys.Get(name)
	if key.Get("priv").Str() != wantPriv || key.Get("pub").Str() != wantPub {
		t.Fatalf("vectors: the rules give key %q other than v3.json's rule derives", name)
	}
	return priv, pub
}

// Material is one organisation's policy material in the rules section, each file as its exact text.
type Material struct {
	// PolicyKey names the organisation's policy key, for RulesKey.
	PolicyKey string
	// Root and Keyring are the text of its signed root and signed keyring, as their files hold them.
	Root, Keyring []byte
	// Proofs are the proofs of its routes, in file order.
	Proofs []RouteProof
	// Entry is a partner's entry service, or "" for an organisation that is no partner.
	Entry string
	// ReplyCert is the text of a partner's reply certificate, or nil.
	ReplyCert []byte
}

// RouteProof is one route's proof, as its text.
type RouteProof struct {
	Route string
	Text  []byte
}

// RulesMaterial returns the material called name.
func RulesMaterial(t testing.TB, name string) Material {
	t.Helper()
	m := Rules(t).Get("material").Get(name)
	out := Material{
		PolicyKey: m.Get("policyKey").Str(),
		Root:      m.Get("root").Raw(),
		Keyring:   m.Get("keyring").Raw(),
	}
	proofs := m.Get("proofs")
	for _, route := range proofs.Names() {
		out.Proofs = append(out.Proofs, RouteProof{Route: route, Text: proofs.Get(route).Raw()})
	}
	if m.Has("entry") {
		out.Entry = m.Get("entry").Str()
	}
	if m.Has("replyCert") {
		out.ReplyCert = m.Get("replyCert").Raw()
	}
	return out
}

// RulesPeer returns the client certificate called name, as DER, and the address it connects from.
func RulesPeer(t testing.TB, name string) (der []byte, remoteAddr string) {
	t.Helper()
	p := Rules(t).Get("peers").Get(name)
	return p.Get("certificate").Hex(), p.Get("remoteAddr").Str()
}

// RulesHandshakeBody returns the body a step posts for the handshake request called name: its JCS bytes.
func RulesHandshakeBody(t testing.TB, name string) []byte {
	t.Helper()
	return Rules(t).Get("handshakeBodies").Get(name).Hex()
}
