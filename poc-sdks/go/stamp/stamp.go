// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

// Version is the protocol version this package reads and writes, a stamp's v. It is the one place in the module
// the number is written: the reader, the writer and the signed bytes all take it from here.
const Version = 4

// signingPrefix is the stamp's domain prefix, which starts its signed bytes (wire.md, Encodings).
const signingPrefix = "paztport-stamp\n"

// Stamp is one hop's signed statement about a request. On the wire it is the object {v, svc, inst, rid,
// ts, sess, rcv, bind, ext, prev, sig}, with v always Version, which a writer adds.
type Stamp struct {
	// Svc is the signing service, whose key a verifier looks up by this name.
	Svc string
	// Inst is the signer's instance, as the signer reports it. It is signed, but only the signer vouches
	// for it.
	Inst string
	// RID is the request id, minted at the origin and carried unchanged by every stamp.
	RID string
	// TS is when the stamp was signed, in milliseconds since the Unix epoch, in [0, 2^53 - 1].
	TS int64
	// Sess is the session id, or "" for a chain in no session.
	Sess string
	// Rcv is the receiver the stamp was signed for: the next stamp's Svc, or for the last stamp, the
	// chain's receiver.
	Rcv string
	// Bind is the binding of what this hop sent.
	Bind string
	// Ext is the commitment to the block of claims the signer attaches (Block.Commit): "" for the empty block.
	// It is compared as text and never decoded.
	Ext string
	// Prev is the previous stamp's Sig, exactly as written, or "" at the origin.
	Prev string
	// Sig is the base64url of the signer's Ed25519 signature over the stamp's signing bytes.
	Sig string
}

// Sign returns f signed with key: f with Sig set to the base64url of key's signature over f's signing
// bytes. Any Sig f holds is ignored. Sign refuses what SigningBytes refuses, and a key that is not
// ed25519.PrivateKeySize bytes.
func Sign(f Stamp, key ed25519.PrivateKey) (Stamp, error) {
	if err := f.fault(); err != nil {
		return Stamp{}, fmt.Errorf("paztport stamp: can't sign: %w", err)
	}
	msg, err := f.signingBytes()
	if err != nil {
		return Stamp{}, fmt.Errorf("paztport stamp: can't sign: %w", err)
	}
	sig, err := keys.Sign(key, msg)
	if err != nil {
		return Stamp{}, fmt.Errorf("paztport stamp: can't sign: %w", err)
	}
	f.Sig = b64.Encode(sig)
	return f, nil
}

// SigningBytes returns the bytes the stamp's signature covers (wire.md, Fields and signed bytes):
//
//	utf8("paztport-stamp\n") || utf8(JCS(the stamp without sig))
//
// the domain prefix, then the canonical bytes of an object of the ten members other than sig, v included. JCS
// escapes every string, so two different stamps never share signed bytes, and a field holding "|" signs like
// any other. They do not depend on Sig. It refuses a stamp no signer may sign: a TS outside [0, 2^53 - 1], or a
// string field that is not valid UTF-8 (the bytes of a lone surrogate among them) or holds a noncharacter. The
// error names the field and never quotes it.
func (s Stamp) SigningBytes() ([]byte, error) {
	if err := s.fault(); err != nil {
		return nil, fmt.Errorf("paztport stamp: no signing bytes: %w", err)
	}
	msg, err := s.signingBytes()
	if err != nil {
		return nil, fmt.Errorf("paztport stamp: no signing bytes: %w", err)
	}
	return msg, nil
}

// Wire returns the stamp's wire bytes, its canonical bytes. It refuses what SigningBytes refuses, and a
// Sig that is not canonical base64url, so a stamp it writes always reads.
func (s Stamp) Wire() ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, fmt.Errorf("paztport stamp: the stamp can't be written: %w", err)
	}
	return wire(s.value())
}

// signingBytes returns the signing bytes of s, whose fields fault has passed. The writer refuses only what fault
// has refused, and an object over the wire limit, which no chain that reads holds.
func (s Stamp) signingBytes() ([]byte, error) {
	b, err := json.Wire(s.object(false))
	if err != nil {
		return nil, err
	}
	return append([]byte(signingPrefix), b...), nil
}

// fault says why no signer may sign s, naming the field, or returns nil if one may.
func (s Stamp) fault() error {
	if s.TS < 0 || s.TS > json.MaxSafe {
		return errors.New("the field ts is not an integer in [0, 2^53 - 1]")
	}
	for _, f := range s.signed() {
		switch {
		case !text.Valid(f.value):
			return fmt.Errorf("the field %s is not valid UTF-8", f.name)
		case text.HasNoncharacter(f.value):
			return fmt.Errorf("the field %s holds a noncharacter", f.name)
		}
	}
	return nil
}

// field is a signed string field, by name.
type field struct {
	name, value string
}

// signed returns the stamp's signed string fields.
func (s Stamp) signed() []field {
	return []field{
		{"svc", s.Svc}, {"inst", s.Inst}, {"rid", s.RID}, {"sess", s.Sess}, {"rcv", s.Rcv},
		{"bind", s.Bind}, {"ext", s.Ext}, {"prev", s.Prev},
	}
}

// writable checks that s reads back as itself once written: it has signing bytes and a canonical Sig.
func (s Stamp) writable() error {
	if err := s.fault(); err != nil {
		return err
	}
	if _, err := b64.Decode(s.Sig); err != nil {
		return errors.New("the field sig is not canonical base64url")
	}
	return nil
}

// value returns the stamp as a JSON object.
func (s Stamp) value() json.Value {
	return s.object(true)
}

// object returns the stamp as a JSON object, with its sig when withSig, and without it for its signed bytes.
// The writer puts the members in JCS order.
func (s Stamp) object(withSig bool) json.Value {
	ms := []json.Member{
		{Name: "v", Value: json.I(Version)},
		{Name: "svc", Value: json.S(s.Svc)},
		{Name: "inst", Value: json.S(s.Inst)},
		{Name: "rid", Value: json.S(s.RID)},
		{Name: "ts", Value: json.I(s.TS)},
		{Name: "sess", Value: json.S(s.Sess)},
		{Name: "rcv", Value: json.S(s.Rcv)},
		{Name: "bind", Value: json.S(s.Bind)},
		{Name: "ext", Value: json.S(s.Ext)},
		{Name: "prev", Value: json.S(s.Prev)},
	}
	if withSig {
		ms = append(ms, json.Member{Name: "sig", Value: json.S(s.Sig)})
	}
	return json.Obj(ms...)
}

// wire returns v's wire bytes, with a writer's refusal in this package's words.
func wire(v json.Value) ([]byte, error) {
	b, err := json.Wire(v)
	if err != nil {
		return nil, fmt.Errorf("paztport stamp: %w", err)
	}
	return b, nil
}
