// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package guard holds the test that keeps the SDK's imports to what it may use.
package guard

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	module  = "github.com/dumbsly/paztport/poc-sdks/go"
	harness = module + "/internal/vectors"
)

// TestNoJSONLibrary reads the imports of every non-test file in the module. The SDK reads and writes JSON
// with its own strict reader and canonical writer, so only the test harness that walks the vector files may
// import encoding/json, and only tests may import the harness. The SDK sends nothing and logs nothing: the
// code that embeds it does both.
func TestNoJSONLibrary(t *testing.T) {
	root := moduleRoot(t)
	harnessReadsJSON := false
	err := filepath.WalkDir(root, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if file != root && ignored(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		pkg := path.Join(module, filepath.ToSlash(filepath.Dir(rel)))
		for _, spec := range f.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if pkg == harness && imp == "encoding/json" {
				harnessReadsJSON = true
			}
			if why := refused(pkg, imp); why != "" {
				t.Errorf("%s imports %s: %s", filepath.ToSlash(rel), imp, why)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The harness is the one importer of encoding/json, so not seeing it means the walk read nothing.
	if !harnessReadsJSON {
		t.Fatal("the walk did not see internal/vectors import encoding/json, so it did not read the module")
	}
}

// TestRefused names each refusal, so that a case taken out of refused fails here, though the module
// imports nothing it refuses.
func TestRefused(t *testing.T) {
	for _, tc := range []struct {
		pkg, imp string
		refused  bool
	}{
		{module + "/paztporthttp", "net", true},
		{module + "/paztporthttp", "net/http", true},
		{module + "/paztporthttp", "net/http/httptest", true},
		{module + "/paztporthttp", "net/url", true},
		{module + "/paztporthttp", "net/netip", true},
		{module + "/stamp", "log", true},
		{module + "/stamp", "log/slog", true},
		{module + "/policy", "encoding/json", true},
		{module + "/policy", "encoding/json/v2", true},
		{module + "/keys", harness, true},
		{harness, "encoding/json", false},
		{module + "/keys", "crypto/ed25519", false},
		{module + "/keys", "network", false},
		{module + "/keys", "logic", false},
		{module + "/keys", "encoding/jsonx", false},
	} {
		if why := refused(tc.pkg, tc.imp); (why != "") != tc.refused {
			t.Errorf("refused(%s, %s) = %q, want refused %v", tc.pkg, tc.imp, why, tc.refused)
		}
	}
}

// refused says why package pkg's non-test code may not import imp, or returns "" when it may.
func refused(pkg, imp string) string {
	switch {
	case within(imp, "encoding/json") && pkg != harness:
		return "the SDK reads and writes JSON with its own reader and writer"
	case imp == harness:
		return "the vector harness is for tests only"
	case within(imp, "net"):
		return "the SDK does no network I/O; the code that embeds it sends the bytes"
	case within(imp, "log"):
		return "the SDK logs nothing; it returns results with reasons"
	}
	return ""
}

// within reports whether import path imp is root or a package beneath it.
func within(imp, root string) bool {
	return imp == root || strings.HasPrefix(imp, root+"/")
}

// ignored reports whether the go command skips a directory of this name.
func ignored(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata"
}

// moduleRoot returns the directory holding go.mod, at or above the working directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod at or above the working directory")
		}
		dir = up
	}
}
