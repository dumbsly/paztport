// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// TestReadsTheJavaKeyring reads a keyring the Java keygen wrote, from PAZTPORT_JAVA_KEYRING or else the Java
// demo's out/keys/keyring.json, and the key files the keygen writes beside it: the policy pin, the policy
// key and the boundary key. ./run test generates them and names the keyring here, so under ./run test this
// check runs or fails, never skips; with neither it skips.
func TestReadsTheJavaKeyring(t *testing.T) {
	path, named := os.LookupEnv("PAZTPORT_JAVA_KEYRING")
	if !named {
		path = filepath.Join("..", "..", "..", "poc-demos", "java-mesh", "out", "keys", "keyring.json")
		if _, err := os.Stat(path); err != nil {
			t.Skipf("no keyring from the Java keygen: set PAZTPORT_JAVA_KEYRING or run ./run java-mesh (%v)", err)
		}
	}
	kf, err := policy.LoadKeyringFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := kf.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) == 0 {
		t.Fatal("the keyring holds no service")
	}
	// The Java keygen and policy tool always sign the keyring, so it verifies under the policy key it names.
	if !kf.Verifies(kf.Policy) {
		t.Fatal("the keyring does not verify under the policy key it names")
	}

	// The key files beside it read as Go reads them, and agree: the keyring verifies under the pin a
	// service would hold, and the policy key's public half is that pin.
	dir := filepath.Dir(path)
	pin, err := keys.LoadPin(filepath.Join(dir, "policy.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !kf.Verifies(pin) {
		t.Fatal("the keyring does not verify under policy.pub")
	}
	priv, err := keys.LoadPrivate(filepath.Join(dir, "policy.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.EncodePublic(priv.Public().(ed25519.PublicKey)); got != pin {
		t.Fatalf("policy.key's public key is %s, not policy.pub's %s", got, pin)
	}
	if _, err := influence.LoadBoundaryKey(filepath.Join(dir, "boundary.key")); err != nil {
		t.Fatal(err)
	}
}
