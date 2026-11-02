// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

var errSigningKey = errors.New("paztport policy: the signing key is not a 64-byte Ed25519 private key")

// signingBytes returns the bytes the policy key signs for a statement of kind what: prefix, then the
// canonical bytes of the object holding members and notAfter. It refuses a notAfter that is not a protocol
// integer, and a member the writer refuses, such as text that is not valid UTF-8.
func signingBytes(what, prefix string, notAfter int64, members ...json.Member) ([]byte, error) {
	if notAfter < 0 || notAfter > json.MaxSafe {
		return nil, fmt.Errorf("paztport policy: a %s's notAfter is not an integer in [0, 2^53 - 1]", what)
	}
	members = append(members, json.Member{Name: "notAfter", Value: json.I(notAfter)})
	body, err := json.Wire(json.Obj(members...))
	if err != nil {
		return nil, fmt.Errorf("paztport policy: the %s has no signing bytes: %w", what, err)
	}
	return append([]byte(prefix), body...), nil
}

// sign returns key's signature over msg as base64url. It refuses a key of the wrong length, where
// ed25519.Sign would panic.
func sign(key ed25519.PrivateKey, msg []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errSigningKey
	}
	return b64.Encode(ed25519.Sign(key, msg)), nil
}

// verifies reports whether sig, as canonical base64url, is pub's signature over msg. It never panics: a key
// or signature of the wrong length is false.
func verifies(pub ed25519.PublicKey, msg []byte, sig string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	s, err := b64.Decode(sig)
	if err != nil || len(s) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, s)
}
