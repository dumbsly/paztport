// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

const replyCertPrefix = "paztport-reply-cert\n"

// ReplyCert is a reply certificate, as reply-cert.json holds it: the policy key's statement that Key is
// service Svc's key until NotAfter. It lets that key sign session replies while the policy key stays
// offline.
//
// A certificate expires because nothing the policy key signed can be withdrawn: retiring the key means not
// issuing it another certificate, so the certificate's lifetime is the key's revocation delay. The policy
// owner issues one only after checking that Key is Svc's key in its current keyring.
type ReplyCert struct {
	// Policy is the policy public key that signed the certificate.
	Policy string
	// Svc is the service whose key the certificate vouches for.
	Svc string
	// Key is that service's public key, as the base64url of its SubjectPublicKeyInfo.
	Key string
	// Sig is the policy key's signature over ReplyCertSigningBytes, as base64url.
	Sig string
	// NotAfter is the last millisecond since the Unix epoch at which the policy owner vouches for Key.
	NotAfter int64
}

var replyCertMembers = []string{"key", "notAfter", "policy", "sig", "svc"}

// ParseReplyCertFile reads a reply certificate file: an object of exactly the strings key, policy, sig and
// svc and notAfter, a protocol integer by its text, so that 1.0 and 1e3 are refused.
func ParseReplyCertFile(b []byte) (ReplyCert, error) {
	return parseFile(b, "reply certificate", replyCertFromValue)
}

// LoadReplyCertFile reads the reply certificate file at path, as ParseReplyCertFile reads bytes.
func LoadReplyCertFile(path string) (ReplyCert, error) {
	return loadFile(path, "reply certificate", replyCertFromValue)
}

// ParseReplyCert reads a reply certificate from its wire bytes, its canonical bytes as a session reply
// carries it, by the rules ParseReplyCertFile reads a file's value.
func ParseReplyCert(wire []byte) (ReplyCert, error) {
	return parseWire(wire, "reply certificate", replyCertFromValue)
}

func replyCertFromValue(v json.Value) (ReplyCert, error) {
	if err := json.Exactly(v, replyCertMembers, nil); err != nil {
		return ReplyCert{}, err
	}
	policy, err := json.String(v, "policy")
	if err != nil {
		return ReplyCert{}, err
	}
	svc, err := json.String(v, "svc")
	if err != nil {
		return ReplyCert{}, err
	}
	key, err := json.String(v, "key")
	if err != nil {
		return ReplyCert{}, err
	}
	sig, err := json.String(v, "sig")
	if err != nil {
		return ReplyCert{}, err
	}
	notAfter, err := json.Integer(v, "notAfter")
	if err != nil {
		return ReplyCert{}, err
	}
	return ReplyCert{Policy: policy, Svc: svc, Key: key, Sig: sig, NotAfter: notAfter}, nil
}

// ReplyCertSigningBytes returns the bytes the policy key signs for a reply certificate:
// "paztport-reply-cert\n" || JCS({key, notAfter, policy, svc}). It refuses a notAfter outside
// [0, 2^53 - 1], and text that is not valid UTF-8, which nothing signs.
func ReplyCertSigningBytes(policy, svc, key string, notAfter int64) ([]byte, error) {
	return signingBytes("reply certificate", replyCertPrefix, notAfter,
		json.Member{Name: "key", Value: json.S(key)},
		json.Member{Name: "policy", Value: json.S(policy)},
		json.Member{Name: "svc", Value: json.S(svc)})
}

// IssueReplyCert signs a certificate that key is service svc's key until notAfter, with the policy key
// signer, whose public key is policy. The caller has already checked that key is svc's key in its current
// keyring, signed by the same policy key.
func IssueReplyCert(policy, svc, key string, notAfter int64, signer ed25519.PrivateKey) (ReplyCert, error) {
	msg, err := ReplyCertSigningBytes(policy, svc, key, notAfter)
	if err != nil {
		return ReplyCert{}, err
	}
	sig, err := sign("reply certificate", signer, msg)
	if err != nil {
		return ReplyCert{}, err
	}
	return ReplyCert{Policy: policy, Svc: svc, Key: key, Sig: sig, NotAfter: notAfter}, nil
}

// Verifies reports whether the certificate names pin as its policy key and its signature verifies under
// that key. It says nothing about time: see Current. It never panics, and a pin that is not a key is false.
func (c ReplyCert) Verifies(pin string) bool {
	if c.Policy != pin {
		return false
	}
	pub, err := keys.ParsePublic(pin)
	if err != nil {
		return false
	}
	msg, err := ReplyCertSigningBytes(c.Policy, c.Svc, c.Key, c.NotAfter)
	return err == nil && verifies(pub, msg, c.Sig)
}

// Current reports whether the policy owner vouches for the certificate at now, in milliseconds since the
// Unix epoch: now <= NotAfter. It says nothing about the signature: see Verifies.
func (c ReplyCert) Current(now int64) bool {
	return now <= c.NotAfter
}

// Wire returns the certificate's wire bytes, its canonical bytes, as a session reply carries it.
func (c ReplyCert) Wire() ([]byte, error) {
	return wire("reply certificate", c.value())
}

func (c ReplyCert) value() json.Value {
	return json.Obj(
		json.Member{Name: "key", Value: json.S(c.Key)},
		json.Member{Name: "notAfter", Value: json.I(c.NotAfter)},
		json.Member{Name: "policy", Value: json.S(c.Policy)},
		json.Member{Name: "sig", Value: json.S(c.Sig)},
		json.Member{Name: "svc", Value: json.S(c.Svc)},
	)
}
