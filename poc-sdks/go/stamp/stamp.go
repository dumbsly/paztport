// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

// version is the stamp version this package reads and writes, its v.
const version = 3

// Stamp is one hop's signed statement about a request. On the wire it is the object {v, svc, inst, rid,
// ts, sess, rcv, bind, infl, prev, sig}, with v always 3, which a writer adds.
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
	// Infl is the commitment to the influence that shaped the call, or "" for none.
	Infl string
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
	sig, err := keys.Sign(key, f.signingBytes())
	if err != nil {
		return Stamp{}, fmt.Errorf("paztport stamp: can't sign: %w", err)
	}
	f.Sig = b64.Encode(sig)
	return f, nil
}

// SigningBytes returns the bytes the stamp's signature covers:
//
//	utf8("3|" svc "|" inst "|" rid "|" ts "|" sess "|" rcv "|" bind "|" infl "|" prev)
//
// with ts in decimal. They do not depend on Sig. It refuses a stamp no signer may sign: a TS outside
// [0, 2^53 - 1], or a signed field that holds "|", is not valid UTF-8 (the bytes of a lone surrogate
// among them) or holds a noncharacter. The error names the field and never quotes it.
func (s Stamp) SigningBytes() ([]byte, error) {
	if err := s.fault(); err != nil {
		return nil, fmt.Errorf("paztport stamp: no signing bytes: %w", err)
	}
	return s.signingBytes(), nil
}

// Wire returns the stamp's wire bytes, its canonical bytes. It refuses what SigningBytes refuses, and a
// Sig that is not canonical base64url, so a stamp it writes always reads.
func (s Stamp) Wire() ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, fmt.Errorf("paztport stamp: the stamp can't be written: %w", err)
	}
	return wire(s.value())
}

// signingBytes returns the signing bytes of s, whose fields fault has passed.
func (s Stamp) signingBytes() []byte {
	b := []byte("3|" + s.Svc + "|" + s.Inst + "|" + s.RID + "|")
	b = strconv.AppendInt(b, s.TS, 10)
	return append(b, "|"+s.Sess+"|"+s.Rcv+"|"+s.Bind+"|"+s.Infl+"|"+s.Prev...)
}

// fault says why no signer may sign s, naming the field, or returns nil if one may.
func (s Stamp) fault() error {
	if s.TS < 0 || s.TS > json.MaxSafe {
		return errors.New("the field ts is not an integer in [0, 2^53 - 1]")
	}
	for _, f := range s.signed() {
		switch {
		case strings.Contains(f.value, "|"):
			return fmt.Errorf(`the field %s holds "|"`, f.name)
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

// signed returns the stamp's signed string fields, in the order they are signed.
func (s Stamp) signed() []field {
	return []field{
		{"svc", s.Svc}, {"inst", s.Inst}, {"rid", s.RID}, {"sess", s.Sess}, {"rcv", s.Rcv},
		{"bind", s.Bind}, {"infl", s.Infl}, {"prev", s.Prev},
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
	return json.Obj(
		json.Member{Name: "v", Value: json.I(version)},
		json.Member{Name: "svc", Value: json.S(s.Svc)},
		json.Member{Name: "inst", Value: json.S(s.Inst)},
		json.Member{Name: "rid", Value: json.S(s.RID)},
		json.Member{Name: "ts", Value: json.I(s.TS)},
		json.Member{Name: "sess", Value: json.S(s.Sess)},
		json.Member{Name: "rcv", Value: json.S(s.Rcv)},
		json.Member{Name: "bind", Value: json.S(s.Bind)},
		json.Member{Name: "infl", Value: json.S(s.Infl)},
		json.Member{Name: "prev", Value: json.S(s.Prev)},
		json.Member{Name: "sig", Value: json.S(s.Sig)},
	)
}

// wire returns v's wire bytes, with a writer's refusal in this package's words.
func wire(v json.Value) ([]byte, error) {
	b, err := json.Wire(v)
	if err != nil {
		return nil, fmt.Errorf("paztport stamp: %w", err)
	}
	return b, nil
}
