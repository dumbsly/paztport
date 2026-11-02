// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// nonceSize is the length of each side's nonce, in bytes.
const nonceSize = 16

// idDomain is the session id's fixed domain byte.
const idDomain = 0x02

// NewNonce returns 16 fresh random bytes, as base64url: a nonce for one handshake.
func NewNonce() string {
	b := make([]byte, nonceSize)
	rand.Read(b) // crypto/rand.Read never returns an error: it fills b or ends the program.
	return b64.Encode(b)
}

// OpensSession reports whether a request read by ParseRequest may open a session at all: its nonce is 16
// bytes, its client root's signature, when it has a root, is 64 bytes, and its policy key and keyring have
// canonical bytes, so that it has a session id. A server answers a request that fails this with an error
// other than Method not found, and leaves its current session, if any, in place.
func OpensSession(req Request) bool {
	nonce, err := b64.Decode(req.Nonce)
	if err != nil || len(nonce) != nonceSize {
		return false
	}
	if sig := rootSig(req.ClientRoot); sig != nil && len(sig) != ed25519.SignatureSize {
		return false
	}
	_, ok := keysHash(req.ClientPolicyKey, req.ClientKeyring)
	return ok
}

// DeriveID returns the session id, which binds both roots, both nonces and the client's policy key and
// keyring:
//
//	b64url(SHA-256(0x02 || flags || clientRootSig || serverRootSig || clientNonce || serverNonce || keysHash))
//
// where flags is 0x01 when the client root is present plus 0x02 when the server root is, and keysHash is
// SHA-256(JCS({"clientKeyring": clientKeyring, "clientPolicyKey": clientPolicyKey})). A nil root signature
// means that side's root is absent; any other, an empty one included, is a present root's decoded sig. It
// returns false, and no id, unless each root signature present is 64 bytes, each nonce 16, and the policy
// key and keyring have canonical bytes. It takes the parts decoded; ID takes a handshake's messages.
func DeriveID(clientRootSig, serverRootSig, clientNonce, serverNonce []byte, clientPolicyKey string,
	clientKeyring map[string]string) (string, bool) {
	digest, ok := keysHash(clientPolicyKey, clientKeyring)
	if !ok || !rootSigSize(clientRootSig) || !rootSigSize(serverRootSig) ||
		len(clientNonce) != nonceSize || len(serverNonce) != nonceSize {
		return "", false
	}
	var flags byte
	if clientRootSig != nil {
		flags |= 0x01
	}
	if serverRootSig != nil {
		flags |= 0x02
	}
	h := sha256.New()
	h.Write([]byte{idDomain, flags})
	h.Write(clientRootSig)
	h.Write(serverRootSig)
	h.Write(clientNonce)
	h.Write(serverNonce)
	h.Write(digest)
	return b64.Encode(h.Sum(nil)), true
}

// ID returns the session id of a handshake of req and a reply with serverRoot, the server's root or nil
// for none, and serverNonce, as base64url: DeriveID over the request's and the reply's members as they
// travel. A root whose sig does not decode is still a present root, so it has no id, never the id of a
// handshake without it. A server fills its reply's Sess with it, and a client checks the reply's Sess
// against it. It returns false, and no id, where DeriveID does.
func ID(req Request, serverRoot *policy.Root, serverNonce string) (string, bool) {
	// A nonce that does not decode is no bytes, which DeriveID refuses as it refuses any length but 16.
	clientNonce, _ := b64.Decode(req.Nonce)
	nonce, _ := b64.Decode(serverNonce)
	return DeriveID(rootSig(req.ClientRoot), rootSig(serverRoot), clientNonce, nonce, req.ClientPolicyKey,
		req.ClientKeyring)
}

// rootSig returns root's decoded sig, or nil when there is no root. A present root's sig is never nil,
// even when it does not decode, so that DeriveID refuses it rather than taking the root as absent.
func rootSig(root *policy.Root) []byte {
	if root == nil {
		return nil
	}
	sig, _ := b64.Decode(root.Sig) // a sig that does not decode is no bytes, which no length allows
	return append([]byte{}, sig...)
}

// rootSigSize reports whether sig is absent (nil) or 64 bytes.
func rootSigSize(sig []byte) bool {
	return sig == nil || len(sig) == ed25519.SignatureSize
}

// keysHash returns SHA-256 of the canonical bytes of {clientKeyring, clientPolicyKey}, and false when they
// have none.
func keysHash(clientPolicyKey string, clientKeyring map[string]string) ([]byte, bool) {
	b, err := json.Wire(json.Obj(
		json.Member{Name: "clientPolicyKey", Value: json.S(clientPolicyKey)},
		json.Member{Name: "clientKeyring", Value: stringMap(clientKeyring)},
	))
	if err != nil {
		return nil, false
	}
	h := sha256.Sum256(b)
	return h[:], true
}
