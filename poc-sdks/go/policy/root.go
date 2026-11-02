// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

const rootPrefix = "paztport-root\n"

// Root is a signed root, as root.json holds it: the root of the allowed routes' Merkle tree under its
// rootId, signed by the policy key until NotAfter. Verifiers pin it, and prove each route against its bytes,
// so a widened tree can't be swapped in without the policy key.
//
// The policy owner signs a root only over a tree whose routes it currently allows. Renewing a root signs the
// same Root text under the same RootID with a new NotAfter, so proofs stay valid; narrowing a policy needs a
// new tree, a new RootID and new proofs.
type Root struct {
	// RootID labels the tree. It is compared for equality, and never derived from the routes.
	RootID string
	// Root is the tree's root, 32 bytes, as base64url. Bytes decodes it.
	Root string
	// Sig is the policy key's signature over RootSigningBytes, as base64url.
	Sig string
	// NotAfter is the last millisecond since the Unix epoch at which the policy owner vouches for the routes.
	NotAfter int64
}

var rootMembers = []string{"notAfter", "root", "rootId", "sig"}

// ParseRootFile reads a root file: an object of exactly the strings root, rootId and sig and notAfter, a
// protocol integer by its text, so that 1798761600000.0 is refused though its value is an integer.
func ParseRootFile(b []byte) (Root, error) {
	return parseFile(b, "root", rootFromValue)
}

// LoadRootFile reads the root file at path, as ParseRootFile reads bytes.
func LoadRootFile(path string) (Root, error) {
	return loadFile(path, "root", rootFromValue)
}

// ParseRoot reads a root from its wire bytes, its canonical bytes as a session request or reply carries
// it, by the rules ParseRootFile reads a file's value.
func ParseRoot(wire []byte) (Root, error) {
	return parseWire(wire, "root", rootFromValue)
}

func rootFromValue(v json.Value) (Root, error) {
	if err := json.Exactly(v, rootMembers, nil); err != nil {
		return Root{}, err
	}
	rootID, err := json.String(v, "rootId")
	if err != nil {
		return Root{}, err
	}
	root, err := json.String(v, "root")
	if err != nil {
		return Root{}, err
	}
	sig, err := json.String(v, "sig")
	if err != nil {
		return Root{}, err
	}
	notAfter, err := json.Integer(v, "notAfter")
	if err != nil {
		return Root{}, err
	}
	return Root{RootID: rootID, Root: root, Sig: sig, NotAfter: notAfter}, nil
}

// RootSigningBytes returns the bytes the policy key signs for a root:
// "paztport-root\n" || JCS({notAfter, root, rootId}), with root as its base64url text. It refuses a notAfter
// outside [0, 2^53 - 1], and text that is not valid UTF-8, which nothing signs.
func RootSigningBytes(rootID, root string, notAfter int64) ([]byte, error) {
	return signingBytes("root", rootPrefix, notAfter,
		json.Member{Name: "root", Value: json.S(root)},
		json.Member{Name: "rootId", Value: json.S(rootID)})
}

// SignRoot signs the tree root, under rootID, with the policy key key, vouching for its routes until
// notAfter. The caller has already checked that the tree's routes are the ones it currently allows.
func SignRoot(root []byte, rootID string, notAfter int64, key ed25519.PrivateKey) (Root, error) {
	if len(root) != sha256.Size {
		return Root{}, errors.New("paztport policy: a tree's root is 32 bytes")
	}
	text := b64.Encode(root)
	msg, err := RootSigningBytes(rootID, text, notAfter)
	if err != nil {
		return Root{}, err
	}
	sig, err := sign("root", key, msg)
	if err != nil {
		return Root{}, err
	}
	return Root{RootID: rootID, Root: text, Sig: sig, NotAfter: notAfter}, nil
}

// Verifies reports whether the root's signature verifies under the policy key pub. It says nothing about
// time: see Current. It never panics, and a key that is not 32 bytes is false.
func (r Root) Verifies(pub ed25519.PublicKey) bool {
	msg, err := RootSigningBytes(r.RootID, r.Root, r.NotAfter)
	return err == nil && verifies(pub, msg, r.Sig)
}

// Current reports whether the policy owner vouches for the root at now, in milliseconds since the Unix
// epoch: now <= NotAfter. It says nothing about the signature: see Verifies.
func (r Root) Current(now int64) bool {
	return now <= r.NotAfter
}

// Bytes returns the tree's root, decoded from Root, which must be canonical base64url.
func (r Root) Bytes() ([]byte, error) {
	b, err := b64.Decode(r.Root)
	if err != nil {
		return nil, errors.New(`paztport policy: the root's "root" is not canonical base64url`)
	}
	return b, nil
}

// File returns the root in the file form root.json holds.
func (r Root) File() ([]byte, error) {
	b, err := json.File(r.value())
	if err != nil {
		return nil, fmt.Errorf("paztport policy: the root can't be written: %w", err)
	}
	return b, nil
}

// Wire returns the root's wire bytes, its canonical bytes, as a session message carries it.
func (r Root) Wire() ([]byte, error) {
	return wire("root", r.value())
}

func (r Root) value() json.Value {
	return json.Obj(
		json.Member{Name: "notAfter", Value: json.I(r.NotAfter)},
		json.Member{Name: "root", Value: json.S(r.Root)},
		json.Member{Name: "rootId", Value: json.S(r.RootID)},
		json.Member{Name: "sig", Value: json.S(r.Sig)},
	)
}
