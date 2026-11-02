// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
)

// The DER that opens each encoding, the same for every Ed25519 key. SubjectPublicKeyInfo is
// SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { no unused bits, the 32-byte key } }, and PKCS#8
// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { the 32-byte seed } } }.
var (
	spkiPrefix  = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	pkcs8Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
)

const (
	notPublic  = "not the base64url of an Ed25519 public key's 44-byte SubjectPublicKeyInfo"
	notPrivate = "not the base64url of an Ed25519 private key's 48-byte PKCS#8"
)

var (
	errPublic  = errors.New("paztport keys: " + notPublic)
	errPrivate = errors.New("paztport keys: " + notPrivate)
)

// ParsePublic returns the public key whose SubjectPublicKeyInfo tok encodes. It refuses tok unless it is
// canonical base64url of exactly 44 bytes: the fixed 12-byte prefix, then the 32-byte key.
func ParsePublic(tok string) (ed25519.PublicKey, error) {
	der, err := b64.Decode(tok)
	if err != nil || len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return nil, errPublic
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}

// EncodePublic returns the base64url of pub's SubjectPublicKeyInfo. It panics if pub is not
// ed25519.PublicKeySize bytes long, as the ed25519 package's own functions do.
func EncodePublic(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		panic("paztport keys: an Ed25519 public key is 32 bytes")
	}
	return b64.Encode(append(bytes.Clone(spkiPrefix), pub...))
}

// ParsePrivate returns the private key whose PKCS#8 tok encodes. It refuses tok unless it is canonical
// base64url of exactly 48 bytes: the fixed 16-byte prefix, then the 32-byte seed.
func ParsePrivate(tok string) (ed25519.PrivateKey, error) {
	der, err := b64.Decode(tok)
	if err != nil || len(der) != len(pkcs8Prefix)+ed25519.SeedSize || !bytes.HasPrefix(der, pkcs8Prefix) {
		return nil, errPrivate
	}
	return ed25519.NewKeyFromSeed(der[len(pkcs8Prefix):]), nil
}

// EncodePrivate returns the base64url of priv's PKCS#8, which holds its seed. It panics if priv is not
// ed25519.PrivateKeySize bytes long, as the ed25519 package's own functions do.
func EncodePrivate(priv ed25519.PrivateKey) string {
	if len(priv) != ed25519.PrivateKeySize {
		panic("paztport keys: an Ed25519 private key is 64 bytes")
	}
	return b64.Encode(append(bytes.Clone(pkcs8Prefix), priv.Seed()...))
}

// LoadPrivate reads a private key file, such as <svc>.key or policy.key: the PKCS#8 text ParsePrivate
// reads, with the whitespace around it trimmed. A refusal names the file and never quotes it.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivate(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("paztport keys: " + path + ": " + notPrivate)
	}
	return key, nil
}

// LoadPin reads a pinned policy key, such as policy.pub: the file's text with the whitespace around it
// trimmed. The pin is not decoded here; a keyring or certificate that names another text, or a pin that is
// not a key, never verifies under it.
func LoadPin(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
