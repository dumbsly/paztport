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
	if !serverSignaturesVerify(r, pin, serverEntry) || !serverCurrent(r, now) {
		return BadSignature
	}
	isAttested := r.Status == StatusAttested
	if isAttested && (r.ServerRoot == nil || req.ClientRoot == nil) {
		return BadSignature
	}
	if sess, ok := ID(req, r.ServerRoot, r.Nonce); !ok || sess != r.Sess {
		return BadSignature
	}
	if isAttested {
		return Attested
	}
	return Unsafe
}

// serverSignaturesVerify reports whether the server's signatures on reply r verify, judged at no time: r
// names pin as its policy key, its sig verifies under the key its form names (replySigner, which checks
// the keyring's and the certificate's signatures in the entry-key form), and its root, when there is one,
// verifies under pin over its own notAfter. Only then does a window r holds count.
func serverSignaturesVerify(r Reply, pin, serverEntry string) bool {
	if r.ServerPolicyKey != pin {
		return false
	}
	pinKey, err := keys.ParsePublic(pin)
	if err != nil {
		return false
	}
	signer, ok := replySigner(r, pinKey, pin, serverEntry)
	return ok && signedBy(r, signer) && (r.ServerRoot == nil || r.ServerRoot.Verifies(pin))
}

// serverCurrent reports whether the server's material in reply r, whose signatures verified, is current
// at now: its root, when there is one, and in the entry-key form its certificate and keyring.
func serverCurrent(r Reply, now int64) bool {
	if r.ServerRoot != nil && !r.ServerRoot.Current(now) {
		return false
	}
	return r.ServerReplyCert == nil || (r.ServerReplyCert.Current(now) && serverKeyring(r).Current(now))
}

// serverKeyring returns the keyring an entry-key reply r presents, with the window its signature was made
// over. A reply that reads holds a keyring signature only beside its window.
func serverKeyring(r Reply) policy.KeyringFile {
	return policy.KeyringFile{
		Services: r.ServerKeyring,
		Policy:   r.ServerPolicyKey,
		Sig:      *r.ServerKeyringSig,
		NotAfter: *r.ServerKeyringNotAfter,
	}
}

// replySigner returns the key reply r's sig must verify under, and false when no key may. The policy-key
// form, with neither the keyring's signature nor a certificate, names the pin, unless the reply has a
// keyring window, which nothing would vouch for there. The entry-key form names the certificate's key,
// and only when both members are present, the keyring and the certificate verify under the pin, and the
// certificate is for serverEntry and names the key the keyring holds for it. The keyring's signature is
// checked over the reply's own window, so a window moved in transit fails it before the window is judged.
// It says nothing about time: serverCurrent judges the certificate and the keyring at the time judged.
func replySigner(r Reply, pinKey ed25519.PublicKey, pin, serverEntry string) (ed25519.PublicKey, bool) {
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
	cert := *r.ServerReplyCert
	entryKey, listed := r.ServerKeyring[serverEntry]
	if !serverKeyring(r).Verifies(pin) || !cert.Verifies(pin) || cert.Svc != serverEntry || !listed ||
		entryKey != cert.Key {
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

// ResponseNotAfterOffline returns the policyNotAfter a response recorded under a recorded handshake's
// reply is checked with (verification.md, Offline verification): the earlier of the server root's notAfter
// and, in the entry-key form, the server keyring's, once the server's signatures over them verify, judged
// at no time. The reply must read and verify against pin, the server policy key the client pinned, and
// serverEntry, the server's entry service from the verifier's own configuration, and its root must verify
// under pin. Whether the session is attested, and the client's side of the handshake, do not decide it.
// It returns false for a reply that does not read, has no server root, or whose signatures do not verify:
// a response relying on it is POLICY_EXPIRED. ResponseNotAfterOffline never panics.
func ResponseNotAfterOffline(reply []byte, pin, serverEntry string) (int64, bool) {
	r, err := ParseReply(reply)
	if err != nil || r.ServerRoot == nil || !serverSignaturesVerify(r, pin, serverEntry) {
		return 0, false
	}
	if r.ServerKeyringSig != nil {
		return min(r.ServerRoot.NotAfter, *r.ServerKeyringNotAfter), true
	}
	return r.ServerRoot.NotAfter, true
}
