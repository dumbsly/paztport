// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// TestReadsTheJavaKeyring reads a keyring the Java keygen wrote, from PAZTPORT_JAVA_KEYRING or else the Java
// demo's out/keys/keyring.json. ./run test generates one and names it here, so under ./run test this check runs
// or fails, never skips; with neither it skips.
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
}
