// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

const replyPrefix = "paztport-session-reply\n"

// The statuses a reply gives, and Status returns.
const (
	attested = "attested"
	unsafe   = "unsafe"
)

// Reply is the server's half of the handshake, signed.
//
// A reply is in the entry-key form when it carries ServerKeyringSig and ServerReplyCert, and Sig is then
// made by the key the certificate names, the server's entry service's own; it is in the policy-key form
// when it carries neither, and the server policy key makes Sig. The form is told only by which members
// are present, so each of the three entry-key form members, and the server root, is a pointer: nil when the
// reply has no such member (or, for the root, has null). A reply with one of the two form members and not
// the other is in neither form, and fails the client's check.
type Reply struct {
	// ServerRoot is the server's signed root, its notAfter inside it, or nil for null.
	ServerRoot *policy.Root
	// ServerPolicyKey is the server's policy public key, which the client pins.
	ServerPolicyKey string
	// ServerKeyring maps each of the server's services, a route node, to its public key.
	ServerKeyring map[string]string
	// ServerKeyringSig is the server policy key's signature over the keyring, in the entry-key form.
	ServerKeyringSig *string
	// ServerKeyringNotAfter is the window ServerKeyringSig was made over, present whenever it is.
	ServerKeyringNotAfter *int64
	// ServerReplyCert is the policy key's certificate for the entry service's key, in the entry-key form.
	ServerReplyCert *policy.ReplyCert
	// Nonce is 16 fresh random bytes from the server, as base64url.
	Nonce string
	// Sess is the session id: see DeriveID.
	Sess string
	// Status is "attested" or "unsafe".
	Status string
	// Disabled lists what the session refuses: the server's unsafe-session list in an unsafe session, and
	// nothing in an attested one.
	Disabled []string
	// Sig is the signature over every other member: see ReplySigningBytes.
	Sig string
}

var (
	replyMembers = []string{"disabled", "nonce", "serverKeyring", "serverPolicyKey", "serverRoot", "sess",
		"sig", "status"}
	// entryKeyMembers are the entry-key form's members, each present only in that form.
	entryKeyMembers = []string{"serverKeyringNotAfter", "serverKeyringSig", "serverReplyCert"}
)

// ParseReply reads a reply from its wire bytes. It refuses bytes that are not exactly the canonical bytes
// of one object with exactly a reply's members: serverRoot null or a signed root with exactly its members,
// string serverPolicyKey, nonce, sess and sig, a serverKeyring object of strings naming each service by a
// route node, status "attested" or "unsafe", a disabled array of strings, and, each only when present, a
// string serverKeyringSig beside a serverKeyringNotAfter, a serverKeyringNotAfter in [0, 2^53 - 1], and a
// serverReplyCert with exactly a reply certificate's members. A member whose value is null is present, so
// a null serverKeyringSig is refused, not taken as absent.
//
// It reads; it checks no signature. A serverKeyringSig that is a string, the empty string included, reads,
// and CheckReply finds that it does not verify.
func ParseReply(b []byte) (Reply, error) {
	v, err := json.ReadWire(b)
	if err != nil {
		return Reply{}, malformed("reply", err)
	}
	r, err := readReply(v)
	if err == nil {
		err = r.check()
	}
	if err != nil {
		return Reply{}, malformed("reply", err)
	}
	return r, nil
}

// readReply reads the members of reply v by their JSON types; check holds the rules beyond them.
func readReply(v json.Value) (Reply, error) {
	if err := json.Exactly(v, replyMembers, entryKeyMembers); err != nil {
		return Reply{}, err
	}
	var r Reply
	var err error
	if r.ServerRoot, err = readRoot(v, "serverRoot"); err != nil {
		return Reply{}, err
	}
	if r.ServerPolicyKey, err = json.String(v, "serverPolicyKey"); err != nil {
		return Reply{}, err
	}
	if r.ServerKeyring, err = readServices(v, "serverKeyring"); err != nil {
		return Reply{}, err
	}
	if _, ok := json.Field(v, "serverKeyringSig"); ok {
		sig, err := json.String(v, "serverKeyringSig")
		if err != nil {
			return Reply{}, err
		}
		r.ServerKeyringSig = &sig
	}
	if _, ok := json.Field(v, "serverKeyringNotAfter"); ok {
		notAfter, err := json.Integer(v, "serverKeyringNotAfter")
		if err != nil {
			return Reply{}, err
		}
		r.ServerKeyringNotAfter = &notAfter
	}
	if field, ok := json.Field(v, "serverReplyCert"); ok {
		b, err := json.Wire(field)
		if err != nil {
			return Reply{}, err
		}
		cert, err := policy.ParseReplyCert(b)
		if err != nil {
			return Reply{}, fmt.Errorf(`the member "serverReplyCert": %w`, err)
		}
		r.ServerReplyCert = &cert
	}
	if r.Nonce, err = json.String(v, "nonce"); err != nil {
		return Reply{}, err
	}
	if r.Sess, err = json.String(v, "sess"); err != nil {
		return Reply{}, err
	}
	if r.Status, err = json.String(v, "status"); err != nil {
		return Reply{}, err
	}
	if r.Disabled, err = readStrings(v, "disabled"); err != nil {
		return Reply{}, err
	}
	if r.Sig, err = json.String(v, "sig"); err != nil {
		return Reply{}, err
	}
	return r, nil
}

// check holds the reply's rules beyond its members' JSON types, which a reader and a writer both apply.
func (r Reply) check() error {
	if r.Status != attested && r.Status != unsafe {
		return errors.New(`the member "status" is neither "attested" nor "unsafe"`)
	}
	if r.ServerKeyringSig != nil && r.ServerKeyringNotAfter == nil {
		return errors.New(`the member "serverKeyringSig" has no "serverKeyringNotAfter" beside it`)
	}
	return routeNodes(r.ServerKeyring, "serverKeyring")
}

// Wire returns the reply's wire bytes, its canonical bytes: Sig with every other member. It refuses a
// reply ParseReply would refuse. A reply ParseReply read writes back to exactly the bytes it was read from.
func (r Reply) Wire() ([]byte, error) {
	b, err := r.wire(true)
	if err != nil {
		return nil, fmt.Errorf("paztport session: the reply can't be written: %w", err)
	}
	return b, nil
}

// ReplySigningBytes returns the bytes a reply's Sig covers:
//
//	"paztport-session-reply\n" || JCS(reply without sig)
//
// every member but sig, with a null root as null and each entry-key form member exactly when present. For
// a reply ParseReply read, these are the bytes received less sig. It refuses a reply Wire refuses.
func ReplySigningBytes(r Reply) ([]byte, error) {
	b, err := r.wire(false)
	if err != nil {
		return nil, fmt.Errorf("paztport session: the reply has no signing bytes: %w", err)
	}
	return append([]byte(replyPrefix), b...), nil
}

// SignReply returns r signed with key, replacing any Sig it has: the entry service's key in the entry-key
// form, the server policy key in the policy-key form. The signature vouches for whatever the reply says, so
// a server sets r.Status to "attested" only when the function Status returns "attested".
func SignReply(r Reply, key ed25519.PrivateKey) (Reply, error) {
	msg, err := ReplySigningBytes(r)
	if err != nil {
		return Reply{}, err
	}
	sig, err := keys.Sign(key, msg)
	if err != nil {
		return Reply{}, err
	}
	r.Sig = b64.Encode(sig)
	return r, nil
}

// wire returns the reply's canonical bytes, with or without sig.
func (r Reply) wire(withSig bool) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	root, err := rootValue(r.ServerRoot)
	if err != nil {
		return nil, err
	}
	members := []json.Member{
		{Name: "serverRoot", Value: root},
		{Name: "serverPolicyKey", Value: json.S(r.ServerPolicyKey)},
		{Name: "serverKeyring", Value: stringMap(r.ServerKeyring)},
		{Name: "nonce", Value: json.S(r.Nonce)},
		{Name: "sess", Value: json.S(r.Sess)},
		{Name: "status", Value: json.S(r.Status)},
		{Name: "disabled", Value: stringArray(r.Disabled)},
	}
	if r.ServerKeyringSig != nil {
		members = append(members, json.Member{Name: "serverKeyringSig", Value: json.S(*r.ServerKeyringSig)})
	}
	if r.ServerKeyringNotAfter != nil {
		members = append(members, json.Member{Name: "serverKeyringNotAfter", Value: json.I(*r.ServerKeyringNotAfter)})
	}
	if r.ServerReplyCert != nil {
		b, err := r.ServerReplyCert.Wire()
		if err != nil {
			return nil, err
		}
		cert, err := json.ReadWire(b)
		if err != nil {
			return nil, err
		}
		members = append(members, json.Member{Name: "serverReplyCert", Value: cert})
	}
	if withSig {
		members = append(members, json.Member{Name: "sig", Value: json.S(r.Sig)})
	}
	return json.Wire(json.Obj(members...))
}

// readStrings reads o's member name, an array of strings.
func readStrings(o json.Value, name string) ([]string, error) {
	v, _ := json.Field(o, name)
	if v.Kind() != json.KindArray {
		return nil, fmt.Errorf("the member %q is not an array", name)
	}
	items := v.Items()
	out := make([]string, len(items))
	for i, item := range items {
		if item.Kind() != json.KindString {
			return nil, fmt.Errorf("the member %q holds a value that is not a string", name)
		}
		out[i] = item.Str()
	}
	return out, nil
}

// stringArray returns ss as an array.
func stringArray(ss []string) json.Value {
	items := make([]json.Value, len(ss))
	for i, s := range ss {
		items[i] = json.S(s)
	}
	return json.Arr(items...)
}
