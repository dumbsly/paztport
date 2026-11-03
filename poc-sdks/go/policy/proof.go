// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// saltSize is the length of every leaf's salt. A leaf hashes salt || route with no separator, so a longer
// salt could take in the start of a route and prove another one.
const saltSize = 16

// Proof is a route's membership proof: the salt of its leaf and the sibling hashes from the leaf's level
// up to the level below the root. A caller sends it with the request whose route it proves; a token of it
// travels in an HTTP header. Copies of a Proof share its slices, as do the proofs a ProofBundle hands out;
// treat them as read-only.
type Proof struct {
	// LeafSalt is the leaf's 16-byte salt.
	LeafSalt []byte
	// Siblings are the 32-byte hashes beside the working hash, one for each level from the leaf up.
	Siblings [][]byte
	// Dirs holds one letter for each sibling: 'L' when the working hash is the left input at that level,
	// 'R' when it is the right.
	Dirs string
	// RootID labels the tree the proof is for.
	RootID string
}

var (
	proofMembers = []string{"dirs", "leafSalt", "rootId", "siblings"}
	errSibling   = errors.New(`the member "siblings" holds a value that is not 32 bytes of canonical base64url`)
)

// ReadProof reads a proof from its token, the base64url of its wire bytes, as ParseProof reads the bytes.
func ReadProof(tok string) (Proof, error) {
	v, err := json.ReadToken(tok)
	if err == nil {
		var p Proof
		if p, err = proofFromValue(v); err == nil {
			return p, nil
		}
	}
	return Proof{}, malformed("proof", err)
}

// ParseProof reads a proof from its wire bytes, its canonical bytes, by the checks of the spec's proof
// object that need no root. The bytes hold an object of exactly the strings dirs, leafSalt and rootId and
// siblings, an array of strings; leafSalt is canonical base64url of 16 bytes and each sibling of 32, and
// dirs holds one 'L' or 'R' for each sibling.
func ParseProof(wire []byte) (Proof, error) {
	return parseWire(wire, "proof", proofFromValue)
}

func proofFromValue(v json.Value) (Proof, error) {
	if err := json.Exactly(v, proofMembers, nil); err != nil {
		return Proof{}, err
	}
	saltText, err := json.String(v, "leafSalt")
	if err != nil {
		return Proof{}, err
	}
	salt, err := b64.Decode(saltText)
	if err != nil || len(salt) != saltSize {
		return Proof{}, errors.New(`the member "leafSalt" is not 16 bytes of canonical base64url`)
	}
	field, _ := json.Field(v, "siblings")
	if field.Kind() != json.KindArray {
		return Proof{}, errors.New(`the member "siblings" is not an array`)
	}
	items := field.Items()
	siblings := make([][]byte, len(items))
	for i, item := range items {
		if item.Kind() != json.KindString {
			return Proof{}, errSibling
		}
		s, err := b64.Decode(item.Str())
		if err != nil || len(s) != sha256.Size {
			return Proof{}, errSibling
		}
		siblings[i] = s
	}
	dirs, err := json.String(v, "dirs")
	if err != nil {
		return Proof{}, err
	}
	if !validDirs(dirs, len(siblings)) {
		return Proof{}, errors.New(`the member "dirs" is not one "L" or "R" for each sibling`)
	}
	rootID, err := json.String(v, "rootId")
	if err != nil {
		return Proof{}, err
	}
	return Proof{LeafSalt: salt, Siblings: siblings, Dirs: dirs, RootID: rootID}, nil
}

// Verify reports whether p proves route against root, the bytes of the root a verifier pins: from the
// leaf of route under p's salt, each level hashes the working hash with its sibling, on the side dirs
// gives, and the last hash is root. Any fault in p is false, never a panic, so a proof built by hand is
// held to the reader's rules. Choosing the pinned root by p.RootID is the caller's.
func (p Proof) Verify(route string, root []byte) bool {
	if len(p.LeafSalt) != saltSize || !validDirs(p.Dirs, len(p.Siblings)) {
		return false
	}
	w, err := LeafHash(p.LeafSalt, route)
	if err != nil {
		return false
	}
	for i, sibling := range p.Siblings {
		// Without a collision only a 32-byte sibling can reach a root, so this length check is defence in
		// depth, as is keys.Verify's of a signature.
		if len(sibling) != sha256.Size {
			return false
		}
		if p.Dirs[i] == 'L' {
			w = NodeHash(w, sibling)
		} else {
			w = NodeHash(sibling, w)
		}
	}
	return bytes.Equal(w, root)
}

// Token returns p's token, the base64url of its canonical bytes, as it travels in a header.
func (p Proof) Token() (string, error) {
	tok, err := json.Token(p.value())
	if err != nil {
		return "", fmt.Errorf("paztport policy: the proof can't be written: %w", err)
	}
	return tok, nil
}

// Wire returns p's wire bytes, its canonical bytes.
func (p Proof) Wire() ([]byte, error) {
	return wire("proof", p.value())
}

func (p Proof) value() json.Value {
	siblings := make([]json.Value, len(p.Siblings))
	for i, s := range p.Siblings {
		siblings[i] = json.S(b64.Encode(s))
	}
	return json.Obj(
		json.Member{Name: "dirs", Value: json.S(p.Dirs)},
		json.Member{Name: "leafSalt", Value: json.S(b64.Encode(p.LeafSalt))},
		json.Member{Name: "rootId", Value: json.S(p.RootID)},
		json.Member{Name: "siblings", Value: json.Arr(siblings...)},
	)
}

// validDirs reports whether dirs is n letters, each 'L' or 'R'.
func validDirs(dirs string, n int) bool {
	if len(dirs) != n {
		return false
	}
	for i := range len(dirs) {
		if dirs[i] != 'L' && dirs[i] != 'R' {
			return false
		}
	}
	return true
}
