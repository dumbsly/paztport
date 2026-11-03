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

// javaKeyFiles are the files the Java keygen writes that the cross-language test reads, in the order it reads them.
var javaKeyFiles = []string{"keyring.json", "policy.pub", "policy.key", "boundary.key"}

// firstMissingKeyFile names the first of javaKeyFiles that dir does not hold as a file, or "" when it holds all.
func firstMissingKeyFile(dir string) string {
	for _, name := range javaKeyFiles {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
			return name
		}
	}
	return ""
}

// TestReadsTheJavaKeyring reads a keyring the Java keygen wrote and the key files it writes beside it: the
// policy pin, the policy key and the boundary key. PAZTPORT_JAVA_KEYRING names the keyring; ./run test generates
// the files and sets it, so there this check runs or fails, never skips. Without it the test looks in the Java
// demo's out/keys and skips unless all four files are there.
func TestReadsTheJavaKeyring(t *testing.T) {
	path, named := os.LookupEnv("PAZTPORT_JAVA_KEYRING")
	if !named {
		dir := filepath.Join("..", "..", "..", "poc-demos", "java-mesh", "out", "keys")
		if missing := firstMissingKeyFile(dir); missing != "" {
			t.Skipf("no %s from the Java keygen in %s: set PAZTPORT_JAVA_KEYRING or run ./run java-mesh", missing, dir)
		}
		path = filepath.Join(dir, "keyring.json")
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
