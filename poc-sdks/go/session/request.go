// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"errors"
	"fmt"
	"maps"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// Request is the client's half of the handshake: its material, presented whole, and a fresh nonce.
//
// ClientKeyringNotAfter travels beside the keyring rather than inside it, because the keyring's wire form
// is a bare map of service keys. The keyring's signature is checked over it (see KeyringFile), so a window
// moved in transit fails that signature, as an altered key does.
type Request struct {
	// ClientRoot is the client's signed root, its notAfter inside it, or nil to ask for an unsafe session.
	ClientRoot *policy.Root
	// ClientPolicyKey is the client's policy public key, as base64url SubjectPublicKeyInfo.
	ClientPolicyKey string
	// ClientKeyring maps each of the client's services, a route node, to its public key.
	ClientKeyring map[string]string
	// ClientKeyringSig is the client policy key's signature over the keyring, never empty.
	ClientKeyringSig string
	// ClientKeyringNotAfter is the keyring's notAfter, which ClientKeyringSig covers.
	ClientKeyringNotAfter int64
	// Nonce is 16 fresh random bytes, as base64url: see NewNonce.
	Nonce string
}

var requestMembers = []string{
	"clientKeyring", "clientKeyringNotAfter", "clientKeyringSig", "clientPolicyKey", "clientRoot", "nonce",
}

// NewRequest returns a request presenting the client's root (nil to ask for an unsafe session), its policy
// key and its signed keyring kf whole (services, signature and window, so that none is left behind), with
// nonce, which is fresh for each handshake. It keeps copies of the root and the services.
func NewRequest(root *policy.Root, policyKey string, kf policy.KeyringFile, nonce string) Request {
	r := Request{
		ClientPolicyKey:       policyKey,
		ClientKeyring:         maps.Clone(kf.Services),
		ClientKeyringSig:      kf.Sig,
		ClientKeyringNotAfter: kf.NotAfter,
		Nonce:                 nonce,
	}
	if root != nil {
		own := *root
		r.ClientRoot = &own
	}
	return r
}

// ParseRequest reads a request from its wire bytes, as a server reads a request it received. It refuses
// bytes that are not exactly the canonical bytes of one object of the request's six members: clientRoot
// null or a signed root with exactly its members, string clientPolicyKey and nonce, a clientKeyring object
// of strings naming each service by a route node, a non-empty string clientKeyringSig and a
// clientKeyringNotAfter in [0, 2^53 - 1]. A server answers a refusal as Invalid params.
//
// It reads; it checks no signature or length. OpensSession and Status judge the request read.
func ParseRequest(b []byte) (Request, error) {
	v, err := json.ReadWire(b)
	if err != nil {
		return Request{}, malformed("request", err)
	}
	return requestFromValue(v)
}

// ReadRequest reads a request from its token, the base64url of its wire bytes, as ParseRequest reads the
// bytes.
func ReadRequest(tok string) (Request, error) {
	v, err := json.ReadToken(tok)
	if err != nil {
		return Request{}, malformed("request", err)
	}
	return requestFromValue(v)
}

func requestFromValue(v json.Value) (Request, error) {
	r, err := readRequest(v)
	if err == nil {
		err = r.check()
	}
	if err != nil {
		return Request{}, malformed("request", err)
	}
	return r, nil
}

// readRequest reads the members of request v by their JSON types; check holds the rules beyond them.
func readRequest(v json.Value) (Request, error) {
	if err := json.Exactly(v, requestMembers, nil); err != nil {
		return Request{}, err
	}
	var r Request
	var err error
	if r.ClientRoot, err = readRoot(v, "clientRoot"); err != nil {
		return Request{}, err
	}
	if r.ClientPolicyKey, err = json.String(v, "clientPolicyKey"); err != nil {
		return Request{}, err
	}
	if r.ClientKeyring, err = readServices(v, "clientKeyring"); err != nil {
		return Request{}, err
	}
	if r.ClientKeyringSig, err = json.String(v, "clientKeyringSig"); err != nil {
		return Request{}, err
	}
	if r.ClientKeyringNotAfter, err = json.Integer(v, "clientKeyringNotAfter"); err != nil {
		return Request{}, err
	}
	if r.Nonce, err = json.String(v, "nonce"); err != nil {
		return Request{}, err
	}
	return r, nil
}

// check holds the request's rules beyond its members' JSON types, which a reader and a writer both apply.
func (r Request) check() error {
	if r.ClientKeyringSig == "" {
		return errors.New(`the member "clientKeyringSig" is empty`)
	}
	return routeNodes(r.ClientKeyring, "clientKeyring")
}

// Wire returns the request's wire bytes, its canonical bytes. It refuses a request ParseRequest would
// refuse, such as one with an empty ClientKeyringSig.
func (r Request) Wire() ([]byte, error) {
	b, err := r.wire()
	if err != nil {
		return nil, fmt.Errorf("paztport session: the request can't be written: %w", err)
	}
	return b, nil
}

func (r Request) wire() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	root, err := rootValue(r.ClientRoot)
	if err != nil {
		return nil, err
	}
	return json.Wire(json.Obj(
		json.Member{Name: "clientRoot", Value: root},
		json.Member{Name: "clientPolicyKey", Value: json.S(r.ClientPolicyKey)},
		json.Member{Name: "clientKeyring", Value: stringMap(r.ClientKeyring)},
		json.Member{Name: "clientKeyringSig", Value: json.S(r.ClientKeyringSig)},
		json.Member{Name: "clientKeyringNotAfter", Value: json.I(r.ClientKeyringNotAfter)},
		json.Member{Name: "nonce", Value: json.S(r.Nonce)},
	))
}

// KeyringFile returns the client's signed keyring as the request presents it, with ClientKeyringNotAfter as
// its window. Whoever checks the keyring against a pin checks this, so that the signature always covers the
// request's own window.
func (r Request) KeyringFile() policy.KeyringFile {
	return policy.KeyringFile{
		Services: maps.Clone(r.ClientKeyring),
		Policy:   r.ClientPolicyKey,
		Sig:      r.ClientKeyringSig,
		NotAfter: r.ClientKeyringNotAfter,
	}
}

// readRoot reads o's member name, null or a signed root, which travels to the policy package as its wire
// bytes. A null root is nil.
func readRoot(o json.Value, name string) (*policy.Root, error) {
	v, _ := json.Field(o, name)
	if v.Kind() == json.KindNull {
		return nil, nil
	}
	b, err := json.Wire(v)
	if err != nil {
		return nil, err
	}
	root, err := policy.ParseRoot(b)
	if err != nil {
		return nil, fmt.Errorf("the member %q: %w", name, err)
	}
	return &root, nil
}

// rootValue returns root as a member's value: null when there is none.
func rootValue(root *policy.Root) (json.Value, error) {
	if root == nil {
		return json.Null(), nil
	}
	b, err := root.Wire()
	if err != nil {
		return json.Value{}, err
	}
	return json.ReadWire(b)
}

// readServices reads o's member name, an object of strings: a keyring's services.
func readServices(o json.Value, name string) (map[string]string, error) {
	v, _ := json.Field(o, name)
	services, err := json.StringMap(v)
	if err != nil {
		return nil, fmt.Errorf("the member %q is not an object of strings", name)
	}
	return services, nil
}

// routeNodes refuses services, the member name, unless it names every service by a route node.
func routeNodes(services map[string]string, name string) error {
	for svc := range services {
		if policy.ValidNode(svc) != nil {
			return fmt.Errorf("the member %q names a service by something that is not a route node", name)
		}
	}
	return nil
}

// stringMap returns m as an object; the writer puts its members in canonical order.
func stringMap(m map[string]string) json.Value {
	members := make([]json.Member, 0, len(m))
	for name, s := range m {
		members = append(members, json.Member{Name: name, Value: json.S(s)})
	}
	return json.Obj(members...)
}

// malformed returns the refusal of a what that does not read, for the reason err gives.
func malformed(what string, err error) error {
	return fmt.Errorf("paztport session: malformed %s: %w", what, err)
}
