// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

const (
	// KeyLength is the length of a boundary key in bytes. A key of any other length is refused, never
	// stretched or cut.
	KeyLength = 32
	// SaltLength is the length of a group's salt in bytes: the first half of an HMAC-SHA256.
	SaltLength = 16
)

// The domain prefixes keep a salt's input and a commitment's from ever matching another hashed form.
const (
	saltDomain  = "paztport-boundary-salt\n"
	entryDomain = "paztport-boundary-entry\n"
)

var (
	errKeyLength = errors.New("paztport influence: the boundary key is not 32 bytes")
	errClass     = errors.New("paztport influence: the class is not one of the four")
)

// ErrNotObject is wrapped by ParseOpening's refusal of bytes that are not the wire bytes of one JSON
// object, as distinct from an object that is not an opening. A checker answering over a service refuses
// such a body as MALFORMED_OPENING, and answers any other body that is refused, or does not open, with
// "does not open".
var ErrNotObject = errors.New("the bytes are not the wire bytes of one JSON object")

// Reduce returns the blinded entries an egress sends in place of es on a call to another organisation,
// whose entry service is rcv, in the request rid; egress is the sending service. The caller passes only
// influence its request context holds after the internal chain passed the live order at this hop.
//
// Reduce normalises es and groups the entries by class and owner, no owner being a group of its own. It
// sends one entry per group: {cls, src: "boundary:<egress>", h, owner}, with h the group's commitment
// below, no cid, and owner left out when the group has none. The sent list is normalised. Every class
// and owner pair of es is in it and no other, so the partner's verdict under PublicWriteRefused is the
// one it would reach on es. No influence gives no entries.
//
// A group's commitment is
//
//	b64url(SHA-256("paztport-boundary-entry\n" || salt || JCS(Normalise(group))))
//
// under the group's Salt. It covers every field of every original, and the salt is per request and per
// partner, so the partner can't tell that two requests carried the same content, or confirm a guess at
// it. The salt is derived, so the sender stores nothing per call to make it.
//
// key is the egress's boundary key, KeyLength bytes, which never leaves the sender and belongs to that
// one egress service and its replicas. Reduce refuses a key of any other length, an empty egress, and
// entries or text that EntriesWire would refuse.
func Reduce(es []Entry, key []byte, rid, rcv, egress string) ([]Entry, error) {
	if len(key) != KeyLength {
		return nil, errKeyLength
	}
	if egress == "" || !text.Valid(egress) || text.HasNoncharacter(egress) {
		return nil, errors.New("paztport influence: the egress is empty, not valid UTF-8 or holds a noncharacter")
	}
	type fact struct {
		class Class
		owner string
	}
	var facts []fact
	groups := map[fact][]Entry{}
	for _, e := range Normalise(es) {
		f := fact{e.Class, e.Owner}
		if _, ok := groups[f]; !ok {
			facts = append(facts, f)
		}
		groups[f] = append(groups[f], e)
	}
	sent := make([]Entry, len(facts))
	for i, f := range facts {
		salt, err := Salt(key, rid, rcv, f.class, f.owner)
		if err != nil {
			return nil, err
		}
		h, err := commitment(salt, groups[f])
		if err != nil {
			return nil, err
		}
		sent[i] = Entry{Class: f.class, Src: "boundary:" + egress, H: h, Owner: f.owner}
	}
	return Normalise(sent), nil
}

// Salt returns the salt of the group of class c and owner owner ("" for none) in the request rid to the
// partner entry rcv, under the boundary key key:
//
//	HMAC-SHA256(key, "paztport-boundary-salt\n" || JCS({cls, owner, rcv, rid}))[0:16]
//
// with owner left out of the object when the group has none. It refuses a key that is not KeyLength
// bytes, a class that is not one of the four, and text that is not valid UTF-8 or holds a noncharacter.
func Salt(key []byte, rid, rcv string, c Class, owner string) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, errKeyLength
	}
	if !c.known() {
		return nil, errClass
	}
	members := []json.Member{
		{Name: "cls", Value: json.S(string(c))},
		{Name: "rcv", Value: json.S(rcv)},
		{Name: "rid", Value: json.S(rid)},
	}
	if owner != "" {
		members = append(members, json.Member{Name: "owner", Value: json.S(owner)})
	}
	input, err := wire("salt's input", json.Obj(members...))
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(saltDomain))
	mac.Write(input)
	return mac.Sum(nil)[:SaltLength], nil
}

// commitment returns the commitment to group under salt, which is SaltLength bytes.
func commitment(salt []byte, group []Entry) (string, error) {
	body, err := EntriesWire(Normalise(group))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(entryDomain))
	h.Write(salt)
	h.Write(body)
	return b64.Encode(h.Sum(nil)), nil
}

// Opening is what a sender reveals to show what one sent entry stood for: the entry's class and owner,
// its group's salt and the original entries. On the wire it is the object {cls, originals, owner, salt},
// with owner left out when absent and salt as base64url.
//
// An opening proves what the sender committed to when it sent the entry, not that the originals were
// true. Revealing one salt opens only its entry: every other group, request and partner has its own
// salt. Two calls to one partner in one request share their salts, so opening one call's entry also
// reveals the salt of the same group's entry in the other.
type Opening struct {
	// Class is the sent entry's class.
	Class Class
	// Originals are the entries the sent entry stood for.
	Originals []Entry
	// Owner is the sent entry's owner, or "" for none.
	Owner string
	// Salt is the group's salt, SaltLength bytes.
	Salt []byte
}

var (
	openingRequired = []string{"cls", "originals", "salt"}
	openingOptional = []string{"owner"}
)

// ParseOpening reads an opening from its wire bytes, its canonical bytes. The bytes hold an object of
// exactly cls, one of the four classes; originals, a list of entries as ParseEntries reads one; salt,
// canonical base64url of SaltLength bytes; and, when present, owner, a non-empty string. Whether the
// opening opens anything is Opens's question, not this one's.
//
// When the bytes do not read as wire bytes, or the value is not an object, the refusal wraps
// ErrNotObject.
func ParseOpening(wire []byte) (Opening, error) {
	v, err := json.ReadWire(wire)
	if err != nil {
		return Opening{}, fmt.Errorf("paztport influence: malformed opening: %w: %w", ErrNotObject, err)
	}
	if v.Kind() != json.KindObject {
		return Opening{}, fmt.Errorf("paztport influence: malformed opening: %w", ErrNotObject)
	}
	o, err := openingFromValue(v)
	if err != nil {
		return Opening{}, malformed("opening", err)
	}
	return o, nil
}

func openingFromValue(v json.Value) (Opening, error) {
	if err := json.Exactly(v, openingRequired, openingOptional); err != nil {
		return Opening{}, err
	}
	c, err := class(v)
	if err != nil {
		return Opening{}, err
	}
	owner, err := owner(v)
	if err != nil {
		return Opening{}, err
	}
	saltText, err := json.String(v, "salt")
	if err != nil {
		return Opening{}, err
	}
	salt, err := b64.Decode(saltText)
	if err != nil || len(salt) != SaltLength {
		return Opening{}, errors.New(`the member "salt" is not 16 bytes of canonical base64url`)
	}
	field, _ := json.Field(v, "originals")
	originals, err := entriesFromValue(field)
	if err != nil {
		return Opening{}, fmt.Errorf(`the member "originals": %w`, err)
	}
	return Opening{Class: c, Originals: originals, Owner: owner, Salt: salt}, nil
}

// Wire returns the opening's wire bytes, its canonical bytes, with Originals in the order given. It
// refuses what ParseOpening would: a Class that is not one of the four, a Salt that is not SaltLength
// bytes, and originals that EntriesWire refuses.
func (o Opening) Wire() ([]byte, error) {
	if !o.Class.known() {
		return nil, errClass
	}
	if len(o.Salt) != SaltLength {
		return nil, errors.New("paztport influence: the opening's salt is not 16 bytes")
	}
	originals, err := entriesValue(o.Originals)
	if err != nil {
		return nil, fmt.Errorf("paztport influence: the opening can't be written: %w", err)
	}
	members := []json.Member{
		{Name: "cls", Value: json.S(string(o.Class))},
		{Name: "originals", Value: originals},
		{Name: "salt", Value: json.S(b64.Encode(o.Salt))},
	}
	if o.Owner != "" {
		members = append(members, json.Member{Name: "owner", Value: json.S(o.Owner)})
	}
	return wire("opening", json.Obj(members...))
}

// Opens reports whether o opens the sent entry sent, which holds only when all of these do:
//
//  1. o has at least one original;
//  2. o's class and owner are sent's, and so are every original's (an absent owner matching only an
//     absent one);
//  3. o's salt is SaltLength bytes;
//  4. the commitment to the originals under the salt is sent's h.
//
// Anything else does not open, whatever o holds: Opens never fails in any other way.
func Opens(sent Entry, o Opening) bool {
	if len(o.Originals) == 0 || len(o.Salt) != SaltLength {
		return false
	}
	if o.Class != sent.Class || o.Owner != sent.Owner {
		return false
	}
	for _, e := range o.Originals {
		if e.Class != sent.Class || e.Owner != sent.Owner {
			return false
		}
	}
	h, err := commitment(o.Salt, o.Originals)
	return err == nil && h == sent.H
}
