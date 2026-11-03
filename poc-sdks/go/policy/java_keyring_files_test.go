// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFirstMissingKeyFile checks the decision between running the cross-language test and skipping it: the
// first of the four files the Java keygen writes that a directory lacks, in the order the test reads them.
func TestFirstMissingKeyFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		present []string
		want    string
	}{
		{"nothing", nil, "keyring.json"},
		{"all four", javaKeyFiles, ""},
		{"no keyring", javaKeyFiles[1:], "keyring.json"},
		{"no policy.pub", []string{"keyring.json", "policy.key", "boundary.key"}, "policy.pub"},
		{"no policy.key", []string{"keyring.json", "policy.pub", "boundary.key"}, "policy.key"},
		{"no boundary.key", javaKeyFiles[:3], "boundary.key"},
		{"only the last two", javaKeyFiles[2:], "keyring.json"},
		{"other files do not count", []string{"orders.key", "gateway.key"}, "keyring.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.present {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := firstMissingKeyFile(dir); got != tc.want {
				t.Errorf("firstMissingKeyFile = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFirstMissingKeyFileNeedsFiles checks that a directory in a file's place does not count as the file.
func TestFirstMissingKeyFileNeedsFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "keyring.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := firstMissingKeyFile(dir); got != "keyring.json" {
		t.Errorf("firstMissingKeyFile = %q, want keyring.json", got)
	}
}
