// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
)

// These tests replay spec/vectors/ed25519.json: crafted keys and signatures the libraries disagree on, with
// answers the file's generator worked out by its own RFC 8032 arithmetic. The three SDKs replay the same
// file, so they refuse the same bytes. They sit inside the package to reach strictEncodings and its constants.

// TestEd25519VectorCount pins the file's size, so a replay of fewer cases than the file holds fails.
func TestEd25519VectorCount(t *testing.T) {
	if got := vectors.Load(t, "ed25519.json").Get("cases").Len(); got != 32 {
		t.Fatalf("ed25519.json holds %d cases, want 32", got)
	}
}

// TestStrictConstantsAreTheVectors checks the small-order y values against the file's, which its generator
// derived from the curve and wrote as 32 little-endian bytes, the order strict.go holds them in.
func TestStrictConstantsAreTheVectors(t *testing.T) {
	file := vectors.Load(t, "ed25519.json").Get("smallOrderY")
	if file.Len() != len(smallOrderY) {
		t.Fatalf("the file lists %d values, strict.go holds %d", file.Len(), len(smallOrderY))
	}
	for i := range smallOrderY {
		if want := file.Index(i).Hex(); !bytes.Equal(smallOrderY[i][:], want) {
			t.Errorf("y #%d = %x, want %x", i, smallOrderY[i], want)
		}
	}
}

// TestEd25519Vectors hands each case to the SDK's own parse and Verify. A key ParsePublic refuses is a key
// that does not verify.
func TestEd25519Vectors(t *testing.T) {
	vectors.Load(t, "ed25519.json").Get("cases").Each(func(_ string, c vectors.Node) {
		name := c.Get("name").Str()
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if got := verifies(t, c); got != c.Get("valid").Bool() {
				t.Fatalf("verifies = %v, want %v", got, !got)
			}
		})
	})
}

// TestEd25519BareLibraryDisagreesOnlyWhereTheCheckIsNeeded calls crypto/ed25519 with nothing in front of it. A case
// where it answers otherwise than the file, yet rules 1 to 4 pass, is one the checks cannot correct: the rule
// would then depend on the Go build, and the SDK must not ship on it. The names it logs are the cases the
// checks exist for.
func TestEd25519BareLibraryDisagreesOnlyWhereTheCheckIsNeeded(t *testing.T) {
	var differs []string
	vectors.Load(t, "ed25519.json").Get("cases").Each(func(_ string, c vectors.Node) {
		c = c.With(t)
		spki := decode(t, c.Get("publicKey").Str())
		if len(spki) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(spki, spkiPrefix) {
			return // no 32-byte key to hand the library
		}
		pub := spki[len(spkiPrefix):]
		sig := decode(t, c.Get("signature").Str())
		name := c.Get("name").Str()
		if len(sig) != ed25519.SignatureSize {
			return // ed25519.Verify panics on a key or signature of another length
		}
		if ed25519.Verify(pub, decode(t, c.Get("message").Str()), sig) == c.Get("valid").Bool() {
			return
		}
		differs = append(differs, name)
		if strictEncodings(pub, sig) {
			t.Errorf("%s: rules 1 to 4 pass, yet crypto/ed25519 answers otherwise than the file", name)
		}
	})
	t.Logf("crypto/ed25519 alone answers otherwise on %d cases: %q", len(differs), differs)
}

func verifies(t *testing.T, c vectors.Node) bool {
	t.Helper()
	pub, err := ParsePublic(c.Get("publicKey").Str())
	if err != nil {
		return false
	}
	return Verify(pub, decode(t, c.Get("message").Str()), decode(t, c.Get("signature").Str()))
}

func decode(t *testing.T, tok string) []byte {
	t.Helper()
	b, err := b64.Decode(tok)
	if err != nil {
		t.Fatalf("the file holds base64url the SDK's decoder refuses: %v", err)
	}
	return b
}
