// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"slices"
	"testing"
)

// core is the packages that verify, carry and record chains and their blocks. They read no extension's items:
// an extension is a set of functions over what the verifier hands on (influence.md), so the core imports none.
var core = []string{
	module + "/stamp",
	module + "/internal/chaincheck",
	module + "/verify",
	module + "/offline",
	module + "/session",
}

// TestTheCoreImportsNoExtension reads the imports of every non-test file in the module: no file of the core's
// packages imports an extension's package. Tests may: a replay can check the core and the extension together.
func TestTheCoreImportsNoExtension(t *testing.T) {
	extensions := []string{module + "/influence", module + "/intent"}
	influenceReadsStamp := false
	files := eachImport(t, func(rel, pkg, imp string) {
		if pkg == module+"/influence" && imp == module+"/stamp" {
			influenceReadsStamp = true
		}
		if !slices.Contains(core, pkg) {
			return
		}
		for _, extension := range extensions {
			if within(imp, extension) {
				t.Errorf("%s imports %s: the core reads no extension's items", rel, imp)
			}
		}
	})
	// The extension builds its blocks with stamp, so not seeing that import, or seeing few files, means the walk
	// did not read the module.
	if files <= 30 || !influenceReadsStamp {
		t.Fatalf("the walk read %d files and saw influence import stamp: %t", files, influenceReadsStamp)
	}
}
