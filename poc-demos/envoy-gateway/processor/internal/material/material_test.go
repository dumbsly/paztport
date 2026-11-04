// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package material_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material/materialtest"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// checks are the errors Load and Ready give, one for each check.
var checks = []error{
	material.ErrKey, material.ErrPin, material.ErrKeyring, material.ErrKeyringPin, material.ErrKeyringExpired,
	material.ErrRoot, material.ErrRootPin, material.ErrRootExpired, material.ErrEdgeKey, material.ErrBundle,
	material.ErrBundleService, material.ErrBundleRoot, material.ErrRoutes, material.ErrNoProof, material.ErrProof,
	material.ErrExpired,
}

// loadFails loads m's material at materialtest.Now and fails the test unless it is refused with want,
// and with no other check's error.
func loadFails(t *testing.T, m *materialtest.Material, want error) {
	t.Helper()
	s, err := material.Load(m.Config, func() int64 { return materialtest.Now })
	if s != nil || err == nil {
		t.Fatalf("Load = %v, %v, want the error %q", s, err, want)
	}
	for _, e := range checks {
		if got := errors.Is(err, e); got != (e == want) {
			t.Errorf("errors.Is(%q, %q) = %t", err, e, got)
		}
	}
}

// otherKey returns a new Ed25519 private key.
func otherKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestLoadAcceptsCompleteMaterial loads current material whose every check holds, and gives back the
// key, bundle and routes it checked.
func TestLoadAcceptsCompleteMaterial(t *testing.T) {
	m := materialtest.New(t)
	s := m.Load(t)
	if !bytes.Equal(s.Key(), m.EdgeKey) {
		t.Error("Key is not the edge's key")
	}
	if b := s.Bundle(); b.Service != "edge" || b.RootID != materialtest.RootID || len(b.Proofs) != 1 {
		t.Errorf("Bundle = %+v", b)
	}
	if rcv, ok := s.Routes().Receiver("shop", "orders"); !ok || rcv != "orders" {
		t.Errorf("Routes maps shop/orders to %q, %t", rcv, ok)
	}
	if err := s.Ready(materialtest.Now); err != nil {
		t.Errorf("Ready at load = %v", err)
	}
}

// TestReadyRefusesOnceMaterialExpires is ready up to and including the earliest notAfter, and from the
// next millisecond refuses with ErrExpired; TimeLeft counts down to it, and below zero after.
func TestReadyRefusesOnceMaterialExpires(t *testing.T) {
	m := materialtest.New(t)
	// The root lasts an hour; the keyring two.
	m.WriteKeyring(t, m.Services(), materialtest.Now+2*materialtest.Lifetime, m.PolicyKey)
	s := m.Load(t)
	end := materialtest.Now + materialtest.Lifetime
	if err := s.Ready(end); err != nil {
		t.Errorf("Ready at the root's notAfter = %v", err)
	}
	if err := s.Ready(end + 1); !errors.Is(err, material.ErrExpired) {
		t.Errorf("Ready past the root's notAfter = %v, want ErrExpired", err)
	}
	if got := s.TimeLeft(materialtest.Now); got != time.Hour {
		t.Errorf("TimeLeft at load = %v, want 1h, the root's", got)
	}
	if got := s.TimeLeft(end + 1000); got != -time.Second {
		t.Errorf("TimeLeft a second past = %v, want -1s", got)
	}
}

// TestTimeLeftHoldsAtTheLongestDuration gives the longest Duration for material whose notAfter is the
// last protocol integer, which in nanoseconds would not fit one.
func TestTimeLeftHoldsAtTheLongestDuration(t *testing.T) {
	const last = 1<<53 - 1
	m := materialtest.New(t)
	m.WriteKeyring(t, m.Services(), last, m.PolicyKey)
	root, err := m.Root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.WriteRoot(t, root, materialtest.RootID, last, m.PolicyKey)
	if got := m.Load(t).TimeLeft(materialtest.Now); got != math.MaxInt64 {
		t.Fatalf("TimeLeft = %v, want the longest Duration", got)
	}
}

// TestLoadRefusesAKeyThatDoesNotLoad refuses a key file that is missing or holds no private key.
func TestLoadRefusesAKeyThatDoesNotLoad(t *testing.T) {
	m := materialtest.New(t)
	m.WriteFile(t, m.Config.KeyPath, m.Pin+"\n")
	loadFails(t, m, material.ErrKey)
	m.Config.KeyPath = filepath.Join(m.Dir, "absent.key")
	loadFails(t, m, material.ErrKey)
}

// TestLoadRefusesAPinThatDoesNotLoad refuses a missing pin file.
func TestLoadRefusesAPinThatDoesNotLoad(t *testing.T) {
	m := materialtest.New(t)
	m.Config.PinPath = filepath.Join(m.Dir, "absent.pub")
	loadFails(t, m, material.ErrPin)
}

// TestLoadRefusesAKeyringThatDoesNotLoad refuses a keyring file that is malformed or missing, and no
// keyring file at all.
func TestLoadRefusesAKeyringThatDoesNotLoad(t *testing.T) {
	m := materialtest.New(t)
	m.WriteFile(t, m.Config.KeyringPaths[0], "{}\n")
	loadFails(t, m, material.ErrKeyring)
	m.Config.KeyringPaths = []string{filepath.Join(m.Dir, "absent.json")}
	loadFails(t, m, material.ErrKeyring)
	m.Config.KeyringPaths = nil
	loadFails(t, m, material.ErrKeyring)
}

// TestLoadRefusesAKeyringNotSignedUnderThePin refuses a keyring signed by another key.
func TestLoadRefusesAKeyringNotSignedUnderThePin(t *testing.T) {
	m := materialtest.New(t)
	m.WriteKeyring(t, m.Services(), materialtest.Now+materialtest.Lifetime, otherKey(t))
	loadFails(t, m, material.ErrKeyringPin)
}

// TestLoadRefusesAnExpiredKeyring refuses a keyring past its notAfter.
func TestLoadRefusesAnExpiredKeyring(t *testing.T) {
	m := materialtest.New(t)
	m.WriteKeyring(t, m.Services(), materialtest.Now-1, m.PolicyKey)
	loadFails(t, m, material.ErrKeyringExpired)
}

// TestLoadRefusesARootThatDoesNotLoad refuses a root file that is malformed or missing, and no root file
// at all.
func TestLoadRefusesARootThatDoesNotLoad(t *testing.T) {
	m := materialtest.New(t)
	m.WriteFile(t, m.Config.RootPaths[0], "[]\n")
	loadFails(t, m, material.ErrRoot)
	m.Config.RootPaths = []string{filepath.Join(m.Dir, "absent.json")}
	loadFails(t, m, material.ErrRoot)
	m.Config.RootPaths = nil
	loadFails(t, m, material.ErrRoot)
}

// TestLoadRefusesARootNotSignedUnderThePin refuses a root signed by another key.
func TestLoadRefusesARootNotSignedUnderThePin(t *testing.T) {
	m := materialtest.New(t)
	root, err := m.Root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.WriteRoot(t, root, materialtest.RootID, materialtest.Now+materialtest.Lifetime, otherKey(t))
	loadFails(t, m, material.ErrRootPin)
}

// TestLoadRefusesAnExpiredRoot refuses a root past its notAfter.
func TestLoadRefusesAnExpiredRoot(t *testing.T) {
	m := materialtest.New(t)
	root, err := m.Root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.WriteRoot(t, root, materialtest.RootID, materialtest.Now-1, m.PolicyKey)
	loadFails(t, m, material.ErrRootExpired)
}

// TestLoadRefusesAKeyringWithAnotherEdgeKey refuses a keyring whose edge key is not the public half of
// the edge's private key, or that names no edge.
func TestLoadRefusesAKeyringWithAnotherEdgeKey(t *testing.T) {
	m := materialtest.New(t)
	services := m.Services()
	services["edge"] = keys.EncodePublic(otherKey(t).Public().(ed25519.PublicKey))
	m.WriteKeyring(t, services, materialtest.Now+materialtest.Lifetime, m.PolicyKey)
	loadFails(t, m, material.ErrEdgeKey)
	delete(services, "edge")
	m.WriteKeyring(t, services, materialtest.Now+materialtest.Lifetime, m.PolicyKey)
	loadFails(t, m, material.ErrEdgeKey)
}

// TestLoadRefusesABundleThatDoesNotLoad refuses a bundle file that is malformed or missing.
func TestLoadRefusesABundleThatDoesNotLoad(t *testing.T) {
	m := materialtest.New(t)
	m.WriteFile(t, m.Config.BundlePath, `{"proofs":{},"rootId":"root-1"}`+"\n")
	loadFails(t, m, material.ErrBundle)
	m.Config.BundlePath = filepath.Join(m.Dir, "absent.json")
	loadFails(t, m, material.ErrBundle)
}

// TestLoadRefusesABundleForAnotherService refuses the bundle of a service that is not edge.
func TestLoadRefusesABundleForAnotherService(t *testing.T) {
	m := materialtest.New(t)
	m.WriteBundle(t, "orders", materialtest.RootID, m.Proofs)
	loadFails(t, m, material.ErrBundleService)
}

// TestLoadRefusesABundleUnderAnUnloadedRoot refuses a bundle whose rootId no loaded root has.
func TestLoadRefusesABundleUnderAnUnloadedRoot(t *testing.T) {
	m := materialtest.New(t)
	m.WriteBundle(t, "edge", "root-2", m.Proofs)
	loadFails(t, m, material.ErrBundleRoot)
}

// TestLoadRefusesNoRoutes refuses a routes map that maps nothing.
func TestLoadRefusesNoRoutes(t *testing.T) {
	m := materialtest.New(t)
	m.Config.Routes = routes.Map{}
	loadFails(t, m, material.ErrRoutes)
}

// TestLoadRefusesAReceiverWithNoProof refuses a mapped receiver whose route from edge the bundle holds
// no proof for.
func TestLoadRefusesAReceiverWithNoProof(t *testing.T) {
	m := materialtest.New(t)
	m.Config.Routes = m.WriteRoutes(t, "shop/orders=orders\nshop/pay=payment\n")
	loadFails(t, m, material.ErrNoProof)
}

// TestLoadRefusesAProofThatDoesNotVerify refuses a mapped receiver's proof that does not prove its route
// against the root with the proof's rootId: another route's proof, or a proof naming a root not loaded.
func TestLoadRefusesAProofThatDoesNotVerify(t *testing.T) {
	m := materialtest.New(t)
	m.WriteBundle(t, "edge", materialtest.RootID,
		map[string]policy.Proof{"edge/orders": m.Proofs["edge/orders/payment"]})
	loadFails(t, m, material.ErrProof)
	p := m.Proofs["edge/orders"]
	p.RootID = "root-2"
	m.WriteBundle(t, "edge", materialtest.RootID, map[string]policy.Proof{"edge/orders": p})
	loadFails(t, m, material.ErrProof)
}
