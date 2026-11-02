// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"errors"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

// The domain prefixes of the tree's two hashes. They keep a 64-byte node from passing as a leaf, the
// second-preimage attack on an unprefixed tree.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

var errLeafText = errors.New("paztport policy: a route that is not valid UTF-8 has no leaf")

// LeafHash returns the leaf hash of route under salt, H(0x00 || salt || utf8(route)). It refuses a route that
// is not valid UTF-8, such as one holding a lone surrogate, which has no UTF-8 form to hash.
func LeafHash(salt []byte, route string) ([]byte, error) {
	if !text.Valid(route) {
		return nil, errLeafText
	}
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(salt)
	h.Write([]byte(route))
	return h.Sum(nil), nil
}

// NodeHash returns the hash of the node over l and r, H(0x01 || l || r).
func NodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}
