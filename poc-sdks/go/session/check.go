// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/ed25519"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// Check is the outcome of the client's check of a reply: the first of its checks that fails, or the
// session's status.
//
// Every outcome but Attested and Unsafe means the server may have opened an attested session the client
// can't use, so the client replaces it: it sends the same request again with no client root and a fresh
// nonce, and trusts the reply to that either way.
type Check string

// The outcomes: the session's status when every check holds, then each check's failure, in the order the
// checks run.
const (
	// Attested: the reply is genuine and the server attested the session.
	Attested Check = "ATTESTED"
	// Unsafe: the reply is genuine and the server opened an unsafe session.
	Unsafe Check = "UNSAFE"
	// MalformedReply: the reply does not read.
	MalformedReply Check = "MALFORMED_REPLY"
	// PinMismatch: the reply names a policy key other than the one the client pinned.
	PinMismatch Check = "PIN_MISMATCH"
	// BadSignature: the reply's signature, a root, the session id, or the server's material at the time
	// judged failed.
	BadSignature Check = "BAD_SIGNATURE"
)

// CheckReply is the client's live check of reply, the bytes it received, against the request req it sent,
// the server policy key pin it pinned, the server's entry service serverEntry from its own configuration
// (never from the reply) and its clock's now. In order, the first failure is the outcome:
//
//  1. the reply reads, by ParseReply (MalformedReply);
//  2. it names pin as its policy key (PinMismatch);
//  3. its signature verifies under the key its form names: in the entry-key form the certificate's key,
//     once the keyring and the certificate verify under pin, the certificate is for serverEntry and names
//     the key the keyring holds for it, and both are current at now; in the policy-key form pin itself,
//     when the reply has no keyring window either. Then, whatever the status, sess is the session id the
//     client derives from req and the reply, and the server's root, when there is one, verifies under pin
//     and is current at now; and an "attested" reply has both roots (BadSignature);
//  4. the reply's status: Attested or Unsafe.
//
// The form is told by which members are present, never by which key verifies, so a reply stripped of its
// certificate, or given one, can't pass under whichever key signed it. The server's material is judged at
// now whatever the reply's status, so a server whose root or keyring has expired is BadSignature, and the
// client takes its replacement path; and an unsafe reply is bound to req as an attested one is. CheckReply
// never panics.
func CheckReply(reply []byte, req Request, pin, serverEntry string, now int64) Check {
	r, err := ParseReply(reply)
	if err != nil {
		return MalformedReply
	}
	if r.ServerPolicyKey != pin {
		return PinMismatch
	}
	pinKey, err := keys.ParsePublic(pin)
	if err != nil {
		return BadSignature
	}
	signer, ok := replySigner(r, pinKey, pin, serverEntry, now)
	if !ok || !signedBy(r, signer) {
		return BadSignature
	}
	isAttested := r.Status == StatusAttested
	if isAttested && (r.ServerRoot == nil || req.ClientRoot == nil) {
		return BadSignature
	}
	if sess, ok := ID(req, r.ServerRoot, r.Nonce); !ok || sess != r.Sess {
		return BadSignature
	}
	if r.ServerRoot != nil && (!r.ServerRoot.Verifies(pin) || !r.ServerRoot.Current(now)) {
		return BadSignature
	}
	if isAttested {
		return Attested
	}
	return Unsafe
}

// replySigner returns the key reply r's sig must verify under, and false when no key may. The policy-key
// form, with neither the keyring's signature nor a certificate, names the pin, unless the reply has a
// keyring window, which nothing would vouch for there. The entry-key form names the certificate's key,
// and only when both members are present, the keyring and the certificate verify under the pin, the
// certificate is for serverEntry and names the key the keyring holds for it, and both are current at now.
// The keyring's signature is checked over the reply's own window, so a window moved in transit fails it
// before the window is judged.
func replySigner(r Reply, pinKey ed25519.PublicKey, pin, serverEntry string, now int64) (ed25519.PublicKey, bool) {
	hasRingSig, hasCert := r.ServerKeyringSig != nil, r.ServerReplyCert != nil
	if !hasRingSig && !hasCert {
		if r.ServerKeyringNotAfter != nil {
			return nil, false
		}
		return pinKey, true
	}
	if !hasRingSig || !hasCert {
		return nil, false
	}
	// A reply that reads holds a keyring signature only beside its window.
	ring := policy.KeyringFile{
		Services: r.ServerKeyring,
		Policy:   r.ServerPolicyKey,
		Sig:      *r.ServerKeyringSig,
		NotAfter: *r.ServerKeyringNotAfter,
	}
	cert := *r.ServerReplyCert
	entryKey, listed := r.ServerKeyring[serverEntry]
	if !ring.Verifies(pin) || !cert.Verifies(pin) || cert.Svc != serverEntry || !listed ||
		entryKey != cert.Key || !cert.Current(now) || !ring.Current(now) {
		return nil, false
	}
	key, err := keys.ParsePublic(cert.Key)
	if err != nil {
		return nil, false
	}
	return key, true
}

// signedBy reports whether r's sig, canonical base64url, is key's signature over its signing bytes.
func signedBy(r Reply, key ed25519.PublicKey) bool {
	msg, err := r.SigningBytes()
	if err != nil {
		return false
	}
	sig, err := b64.Decode(r.Sig)
	return err == nil && keys.Verify(key, msg, sig)
}

// AttestedOffline reports whether a recorded handshake opened an attested session, judged at at, the time
// of the record being judged (a call's last stamp's ts, which the client signed), never a time read from
// the handshake record, which anyone holding it can edit. The reply, as recorded, must pass CheckReply at
// at as Attested, against the recorded pin and the server's entry service from the verifier's own
// configuration; and the client's root and keyring must verify under its policy key and be current at at.
//
// There is no client pin offline: the server's signed "attested" reply, whose session id binds the
// client's policy key and keyring, is its statement that it pinned them. AttestedOffline never panics.
func AttestedOffline(reply []byte, req Request, pin, serverEntry string, at int64) bool {
	if CheckReply(reply, req, pin, serverEntry, at) != Attested {
		return false
	}
	// An attested reply has passed with both roots present.
	ring := req.KeyringFile()
	return ring.Verifies(req.ClientPolicyKey) && req.ClientRoot.Verifies(req.ClientPolicyKey) &&
		req.ClientRoot.Current(at) && ring.Current(at)
}
