// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

const keyringPrefix = "paztport-keyring\n"

// Keyring is each service's public key, by the service's name: the keys of a keyring that verified.
type Keyring map[string]ed25519.PublicKey

// KeyringFile is a signed keyring, as keyring.json holds it: the policy key and every service's public key,
// each as the base64url of its SubjectPublicKeyInfo, signed by the policy key until NotAfter.
//
// A verifier pins the policy key out of band and trusts the service keys only when the keyring verifies
// under that pin and is current: a keyring does not vouch for its own policy key. The policy owner signs a
// keyring only after checking that each key is its service's current key.
type KeyringFile struct {
	// Services maps each service's name, a route node, to its public key.
	Services map[string]string
	// Policy is the policy public key that signed the keyring.
	Policy string
	// Sig is the policy key's signature over KeyringSigningBytes, as base64url.
	Sig string
	// NotAfter is the last millisecond since the Unix epoch at which the policy owner vouches for the keys.
	NotAfter int64
}

var keyringMembers = []string{"notAfter", "policy", "services", "sig"}

// errServiceName refuses a keyring that names a service by something that is not a route node.
var errServiceName = errors.New("paztport policy: the keyring names a service by something that is not a route node")

// ParseKeyringFile reads a keyring file: an object of exactly a string policy, a string sig, a services
// object naming each service by a route node, its every value a string, and notAfter, a protocol integer by
// its text, so that 1798761600000.0 is refused though its value is an integer.
func ParseKeyringFile(b []byte) (KeyringFile, error) {
	return parseFile(b, "keyring", keyringFromValue)
}

// LoadKeyringFile reads the keyring file at path, as ParseKeyringFile reads bytes.
func LoadKeyringFile(path string) (KeyringFile, error) {
	return loadFile(path, "keyring", keyringFromValue)
}

func keyringFromValue(v json.Value) (KeyringFile, error) {
	if err := json.Exactly(v, keyringMembers, nil); err != nil {
		return KeyringFile{}, err
	}
	field, _ := json.Field(v, "services")
	services, err := json.StringMap(field)
	if err != nil {
		return KeyringFile{}, errors.New(`the member "services" is not an object of strings`)
	}
	if !routeNodes(services) {
		return KeyringFile{}, errors.New(`the member "services" names a service by something that is not a route node`)
	}
	policy, err := json.String(v, "policy")
	if err != nil {
		return KeyringFile{}, err
	}
	sig, err := json.String(v, "sig")
	if err != nil {
		return KeyringFile{}, err
	}
	notAfter, err := json.Integer(v, "notAfter")
	if err != nil {
		return KeyringFile{}, err
	}
	return KeyringFile{Services: services, Policy: policy, Sig: sig, NotAfter: notAfter}, nil
}

// KeyringSigningBytes returns the bytes the policy key signs for a keyring:
// "paztport-keyring\n" || JCS({notAfter, policy, services}). It refuses a notAfter outside [0, 2^53 - 1],
// and text that is not valid UTF-8, which nothing signs.
func KeyringSigningBytes(policy string, services map[string]string, notAfter int64) ([]byte, error) {
	return signingBytes("keyring", keyringPrefix, notAfter,
		json.Member{Name: "policy", Value: json.S(policy)},
		json.Member{Name: "services", Value: servicesValue(services)})
}

// SignKeyring signs services under the policy key key, whose public key is policy, vouching for them until
// notAfter. The caller has already checked that each key is its service's current key. It refuses a service
// name that is not a route node, which every reader refuses, before signing.
func SignKeyring(
	services map[string]string, policy string, notAfter int64, key ed25519.PrivateKey,
) (KeyringFile, error) {
	if !routeNodes(services) {
		return KeyringFile{}, errServiceName
	}
	msg, err := KeyringSigningBytes(policy, services, notAfter)
	if err != nil {
		return KeyringFile{}, err
	}
	sig, err := sign("keyring", key, msg)
	if err != nil {
		return KeyringFile{}, err
	}
	return KeyringFile{Services: maps.Clone(services), Policy: policy, Sig: sig, NotAfter: notAfter}, nil
}

// Verifies reports whether the keyring names pin as its policy key and its signature verifies under that
// key. It says nothing about time: see Current. It never panics; a pin that is not a key is false, and so is
// a keyring built in code that names a service by something that is not a route node, which no reader keeps.
func (kf KeyringFile) Verifies(pin string) bool {
	if kf.Policy != pin || !routeNodes(kf.Services) {
		return false
	}
	pub, err := keys.ParsePublic(pin)
	if err != nil {
		return false
	}
	msg, err := KeyringSigningBytes(kf.Policy, kf.Services, kf.NotAfter)
	return err == nil && verifies(pub, msg, kf.Sig)
}

// Current reports whether the policy owner vouches for the keyring at now, in milliseconds since the Unix
// epoch: now <= NotAfter. It says nothing about the signature: see Verifies.
func (kf KeyringFile) Current(now int64) bool {
	return now <= kf.NotAfter
}

// Keyring returns the service keys, decoded. It refuses a keyring that names a service by something that is
// not a route node, or holds a key that is not an Ed25519 public key, and names no service in the refusal.
func (kf KeyringFile) Keyring() (Keyring, error) {
	if !routeNodes(kf.Services) {
		return nil, errServiceName
	}
	k := make(Keyring, len(kf.Services))
	for name, text := range kf.Services {
		pub, err := keys.ParsePublic(text)
		if err != nil {
			return nil, errors.New("paztport policy: the keyring holds a service key that is not an Ed25519 public key")
		}
		k[name] = pub
	}
	return k, nil
}

// File returns the keyring in the file form keyring.json holds.
func (kf KeyringFile) File() ([]byte, error) {
	b, err := json.File(json.Obj(
		json.Member{Name: "notAfter", Value: json.I(kf.NotAfter)},
		json.Member{Name: "policy", Value: json.S(kf.Policy)},
		json.Member{Name: "services", Value: servicesValue(kf.Services)},
		json.Member{Name: "sig", Value: json.S(kf.Sig)},
	))
	if err != nil {
		return nil, fmt.Errorf("paztport policy: the keyring can't be written: %w", err)
	}
	return b, nil
}

// routeNodes reports whether every name in services is a valid service name: a route node holding no '#'.
func routeNodes(services map[string]string) bool {
	for name := range services {
		if ValidService(name) != nil {
			return false
		}
	}
	return true
}

// servicesValue returns services as an object; the writer puts its members in canonical order.
func servicesValue(services map[string]string) json.Value {
	members := make([]json.Member, 0, len(services))
	for name, key := range services {
		members = append(members, json.Member{Name: name, Value: json.S(key)})
	}
	return json.Obj(members...)
}
