// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package materialtest writes the edge's policy material for tests, as the Java tools would: a policy key
// and its pin, the edge's private key, a keyring and a root signed under the policy key, a proof bundle
// for the edge's routes, and a routes file. Each test gets its own files, which it may rewrite to break
// one check at a time. It also gives the route metadata Envoy sends with a request on a mapped route.
package materialtest

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// Now is the time the material is made at, in milliseconds since the Unix epoch.
const Now int64 = 1767225600000

// Lifetime is how long the material is current after Now, in milliseconds.
const Lifetime int64 = 3600000

// RootID is the rootId of the tree the material's root and proofs belong to.
const RootID = "root-1"

// Material is one set of the edge's policy material, written to files.
type Material struct {
	// Config names the files and holds the routes: the HTTPRoute shop/orders mapped to orders.
	Config material.Config
	// Dir is the directory the files are in.
	Dir string
	// PolicyKey signs the keyring and the root, and Pin is its public key as policy.pub holds it.
	PolicyKey ed25519.PrivateKey
	Pin       string
	// EdgeKey is the edge's private key; OrdersKey and PaymentKey the receivers'.
	EdgeKey, OrdersKey, PaymentKey ed25519.PrivateKey
	// Keyring and Root are the files written, each current until Now + Lifetime.
	Keyring policy.KeyringFile
	Root    policy.Root
	// Proofs are the proofs of the tree's routes, edge/orders and edge/orders/payment, by route.
	Proofs map[string]policy.Proof
}

// New writes a complete, current set of material into a new directory: the routes edge/orders and
// edge/orders/payment are allowed, and the edge's bundle holds the proof of edge/orders.
func New(t testing.TB) *Material {
	t.Helper()
	m := &Material{Dir: t.TempDir()}
	var policyPub ed25519.PublicKey
	policyPub, m.PolicyKey = genKey(t)
	m.Pin = keys.EncodePublic(policyPub)
	_, m.EdgeKey = genKey(t)
	_, m.OrdersKey = genKey(t)
	_, m.PaymentKey = genKey(t)

	m.Config = material.Config{
		KeyPath:      filepath.Join(m.Dir, "edge.key"),
		PinPath:      filepath.Join(m.Dir, "policy.pub"),
		KeyringPaths: []string{filepath.Join(m.Dir, "keyring.json")},
		RootPaths:    []string{filepath.Join(m.Dir, "root.json")},
		BundlePath:   filepath.Join(m.Dir, "proofs-edge.json"),
		Routes:       m.WriteRoutes(t, "shop/orders=orders\n"),
	}
	m.WriteFile(t, m.Config.KeyPath, keys.EncodePrivate(m.EdgeKey)+"\n")
	m.WriteFile(t, m.Config.PinPath, m.Pin+"\n")
	m.Keyring = m.WriteKeyring(t, m.Services(), Now+Lifetime, m.PolicyKey)

	// A tree of two leaves: edge/orders on the left, edge/orders/payment on the right.
	salts := [][]byte{fill(16, 1), fill(16, 2)}
	routeNames := []string{"edge/orders", "edge/orders/payment"}
	leaves := make([][]byte, 2)
	for i, r := range routeNames {
		leaf, err := policy.LeafHash(salts[i], r)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = leaf
	}
	m.Proofs = map[string]policy.Proof{
		routeNames[0]: {LeafSalt: salts[0], Siblings: [][]byte{leaves[1]}, Dirs: "L", RootID: RootID},
		routeNames[1]: {LeafSalt: salts[1], Siblings: [][]byte{leaves[0]}, Dirs: "R", RootID: RootID},
	}
	m.Root = m.WriteRoot(t, policy.NodeHash(leaves[0], leaves[1]), RootID, Now+Lifetime, m.PolicyKey)
	m.WriteBundle(t, "edge", RootID, map[string]policy.Proof{routeNames[0]: m.Proofs[routeNames[0]]})
	return m
}

// Services returns the keyring's services: edge, orders and payment, each with its public key. The map is
// the caller's to change.
func (m *Material) Services() map[string]string {
	return map[string]string{
		"edge":    keys.EncodePublic(m.EdgeKey.Public().(ed25519.PublicKey)),
		"orders":  keys.EncodePublic(m.OrdersKey.Public().(ed25519.PublicKey)),
		"payment": keys.EncodePublic(m.PaymentKey.Public().(ed25519.PublicKey)),
	}
}

// WriteKeyring signs a keyring of services with key, naming the pin, and writes it over the first keyring
// file.
func (m *Material) WriteKeyring(
	t testing.TB, services map[string]string, notAfter int64, key ed25519.PrivateKey,
) policy.KeyringFile {
	t.Helper()
	return m.writeKeyring(t, 0, services, notAfter, key)
}

// writeKeyring signs a keyring and writes it over the i'th keyring file.
func (m *Material) writeKeyring(
	t testing.TB, i int, services map[string]string, notAfter int64, key ed25519.PrivateKey,
) policy.KeyringFile {
	t.Helper()
	kf, err := policy.SignKeyring(services, m.Pin, notAfter, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := kf.File()
	if err != nil {
		t.Fatal(err)
	}
	m.WriteFile(t, m.Config.KeyringPaths[i], string(b))
	return kf
}

// AddKeyring signs another keyring of services with key, naming the pin, writes it to a new file and
// adds that file to Config.KeyringPaths, as a rollover pins an old and a new keyring together.
func (m *Material) AddKeyring(
	t testing.TB, services map[string]string, notAfter int64, key ed25519.PrivateKey,
) policy.KeyringFile {
	t.Helper()
	m.Config.KeyringPaths = append(m.Config.KeyringPaths,
		filepath.Join(m.Dir, fmt.Sprintf("keyring-%d.json", len(m.Config.KeyringPaths))))
	return m.writeKeyring(t, len(m.Config.KeyringPaths)-1, services, notAfter, key)
}

// AddRoot signs another root with key, writes it to a new file and adds that file to Config.RootPaths.
func (m *Material) AddRoot(
	t testing.TB, root []byte, rootID string, notAfter int64, key ed25519.PrivateKey,
) policy.Root {
	t.Helper()
	m.Config.RootPaths = append(m.Config.RootPaths,
		filepath.Join(m.Dir, fmt.Sprintf("root-%d.json", len(m.Config.RootPaths))))
	return m.writeRoot(t, len(m.Config.RootPaths)-1, root, rootID, notAfter, key)
}

// WriteRoot signs a root with key and writes it over the first root file.
func (m *Material) WriteRoot(
	t testing.TB, root []byte, rootID string, notAfter int64, key ed25519.PrivateKey,
) policy.Root {
	t.Helper()
	return m.writeRoot(t, 0, root, rootID, notAfter, key)
}

// writeRoot signs a root and writes it over the i'th root file.
func (m *Material) writeRoot(
	t testing.TB, i int, root []byte, rootID string, notAfter int64, key ed25519.PrivateKey,
) policy.Root {
	t.Helper()
	r, err := policy.SignRoot(root, rootID, notAfter, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.File()
	if err != nil {
		t.Fatal(err)
	}
	m.WriteFile(t, m.Config.RootPaths[i], string(b))
	return r
}

// WriteBundle writes a proof bundle for service, under rootID, holding proofs, over the bundle file.
// Every route and name must be plain ASCII, which is written as it is.
func (m *Material) WriteBundle(t testing.TB, service, rootID string, proofs map[string]policy.Proof) {
	t.Helper()
	members := make([]string, 0, len(proofs))
	for r, p := range proofs {
		b, err := p.Wire()
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, quote(t, r)+":"+string(b))
	}
	m.WriteFile(t, m.Config.BundlePath, fmt.Sprintf(`{"proofs":{%s},"rootId":%s,"service":%s}`+"\n",
		strings.Join(members, ","), quote(t, rootID), quote(t, service)))
}

// WriteRoutes writes text as the routes file and returns the map it loads as.
func (m *Material) WriteRoutes(t testing.TB, text string) routes.Map {
	t.Helper()
	path := filepath.Join(m.Dir, "routes.txt")
	m.WriteFile(t, path, text)
	rm, err := routes.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return rm
}

// WriteFile writes text to path.
func (m *Material) WriteFile(t testing.TB, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Load loads the material at Now.
func (m *Material) Load(t testing.TB) *material.Set {
	t.Helper()
	s, err := material.Load(m.Config, func() int64 { return Now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RouteMetadata returns the xds.route_metadata attribute Envoy sends for a request on the HTTPRoute
// ns/name, in the text form the captured fixture in the routes package shows, with no policies attached.
// ns and name must be plain ASCII with no quote or backslash, which is written as it is.
func RouteMetadata(ns, name string) string {
	return `filter_metadata { key: "envoy-gateway" value { fields { key: "resources" value { list_value { ` +
		`values { struct_value { fields { key: "kind" value { string_value: "HTTPRoute" } } ` +
		`fields { key: "name" value { string_value: "` + name + `" } } ` +
		`fields { key: "namespace" value { string_value: "` + ns + `" } } } } } } } } } `
}

// genKey returns a new Ed25519 key pair.
func genKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// fill returns n bytes of b.
func fill(n int, b byte) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// quote returns s as a JSON string. It takes only printable ASCII with no quote or backslash, which
// needs no escape.
func quote(t testing.TB, s string) string {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			t.Fatalf("materialtest writes only plain ASCII names, not %q", s)
		}
	}
	return `"` + s + `"`
}
