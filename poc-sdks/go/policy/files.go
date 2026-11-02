// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"
	"os"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// parseFile reads b as a file holding an object of kind what, which build makes from the value read.
func parseFile[T any](b []byte, what string, build func(json.Value) (T, error)) (T, error) {
	t, err := readFile(b, build)
	if err != nil {
		var zero T
		return zero, malformed(what+" file", err)
	}
	return t, nil
}

// parseWire reads b as the wire bytes of an object of kind what, which build makes from the value read.
func parseWire[T any](b []byte, what string, build func(json.Value) (T, error)) (T, error) {
	v, err := json.ReadWire(b)
	if err == nil {
		var t T
		if t, err = build(v); err == nil {
			return t, nil
		}
	}
	var zero T
	return zero, malformed(what, err)
}

// wire returns v's canonical bytes, the wire form of an object of kind what.
func wire(what string, v json.Value) ([]byte, error) {
	b, err := json.Wire(v)
	if err != nil {
		return nil, fmt.Errorf("paztport policy: the %s can't be written: %w", what, err)
	}
	return b, nil
}

// loadFile reads the file at path as parseFile reads bytes, and names the file in a refusal. A file that
// can't be read is the *fs.PathError that says why.
func loadFile[T any](path, what string, build func(json.Value) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	// One byte past the limit is all the reader needs to refuse the file at the size step, so a file of any
	// size is read no further.
	b, err := io.ReadAll(io.LimitReader(f, json.FileBytes+1))
	if err != nil {
		return zero, err
	}
	t, err := readFile(b, build)
	if err != nil {
		return zero, malformed(what+" file "+path, err)
	}
	return t, nil
}

func readFile[T any](b []byte, build func(json.Value) (T, error)) (T, error) {
	v, err := json.ReadFile(b)
	if err != nil {
		var zero T
		return zero, err
	}
	return build(v)
}

// malformed returns the refusal of an object of kind what, for the reason err gives.
func malformed(what string, err error) error {
	return fmt.Errorf("paztport policy: malformed %s: %w", what, err)
}
