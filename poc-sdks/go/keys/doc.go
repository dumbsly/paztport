// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package keys reads and writes the protocol's Ed25519 keys and the files that hold them.
//
// A public key travels as the base64url of its X.509 SubjectPublicKeyInfo DER, 44 bytes, and a private key
// as the base64url of its PKCS#8 DER, 48 bytes that end in the key's 32-byte seed. An Ed25519 key has one
// such layout each, so the readers here take the exact bytes the spec gives and nothing else: no other
// algorithm, no optional attribute, no public key beside the seed.
//
// A key file holds one such text, and its readers trim the space, tab, line feed and carriage return around
// it, JSON's whitespace, and nothing else. A pin, the policy public key a service trusts, is kept as its
// text: it is compared with a keyring's policy key as text, and decoded only to verify a signature.
//
// Sign and Verify are the module's one guard around crypto/ed25519: they check every key's and signature's
// length first, so that no input reaches a call that would panic on it.
package keys
