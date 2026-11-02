// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

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

// sign returns key's signature over msg, the signing bytes of a statement of kind what, as base64url, as
// the statement's sig holds it.
func sign(what string, key ed25519.PrivateKey, msg []byte) (string, error) {
	sig, err := keys.Sign(key, msg)
	if err != nil {
		return "", fmt.Errorf("paztport policy: can't sign the %s: %w", what, err)
	}
	return b64.Encode(sig), nil
}

// verifies reports whether sig, which must be canonical base64url, is pub's signature over msg.
func verifies(pub ed25519.PublicKey, msg []byte, sig string) bool {
	s, err := b64.Decode(sig)
	return err == nil && keys.Verify(pub, msg, s)
}
