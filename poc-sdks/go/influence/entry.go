// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// Entry is one piece of content that was in the context when an action was decided. On the wire it is
// the object {cls, src, h, cid, owner}, with cid and owner left out when absent.
type Entry struct {
	// Class is the content's class.
	Class Class
	// Src names the source, such as "server:<serverId>", "web:example.com", "http:<target>" for an HTTP
	// response, or "boundary:<egress>" for a blinded entry from another organisation.
	Src string
	// H identifies the content, such as a hash of it.
	H string
	// CID is the content id from the label the entry came from. It is present only when HasCID is set,
	// and a present cid may be "".
	CID string
	// HasCID reports whether the entry has a cid.
	HasCID bool
	// Owner is an opaque id of whose data this is, or "" when the entry has no owner. A present owner is
	// never empty on the wire, so an empty one can't be taken for a known one.
	Owner string
}

var (
	entryRequired = []string{"cls", "h", "src"}
	entryOptional = []string{"cid", "owner"}
)

// ReadEntries reads a list of entries from its token, the base64url of its wire bytes, as ParseEntries
// reads the bytes.
func ReadEntries(tok string) ([]Entry, error) {
	v, err := json.ReadToken(tok)
	if err == nil {
		var es []Entry
		if es, err = entriesFromValue(v); err == nil {
			return es, nil
		}
	}
	return nil, malformed("influence", err)
}

// ParseEntries reads a list of entries from its wire bytes, its canonical bytes. The bytes hold an array
// whose every item is an object of exactly an entry's members: cls, one of the four classes; the strings
// src and h; and, when present, the string cid and owner, a non-empty string. The entries keep the order
// they were read in.
//
// A verifier reports a list that is refused here, or bytes that do not read, as INFLUENCE_MISMATCH.
func ParseEntries(wire []byte) ([]Entry, error) {
	return parseWire(wire, "influence", entriesFromValue)
}

func entriesFromValue(v json.Value) ([]Entry, error) {
	if v.Kind() != json.KindArray {
		return nil, errors.New("the value is not an array")
	}
	items := v.Items()
	es := make([]Entry, len(items))
	for i, item := range items {
		e, err := entryFromValue(item)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		es[i] = e
	}
	return es, nil
}

func entryFromValue(o json.Value) (Entry, error) {
	if err := json.Exactly(o, entryRequired, entryOptional); err != nil {
		return Entry{}, err
	}
	c, err := readClass(o)
	if err != nil {
		return Entry{}, err
	}
	src, err := json.String(o, "src")
	if err != nil {
		return Entry{}, err
	}
	h, err := json.String(o, "h")
	if err != nil {
		return Entry{}, err
	}
	var cid string
	_, hasCID := json.Field(o, "cid")
	if hasCID {
		if cid, err = json.String(o, "cid"); err != nil {
			return Entry{}, err
		}
	}
	owner, err := readOwner(o)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Class: c, Src: src, H: h, CID: cid, HasCID: hasCID, Owner: owner}, nil
}

// EntriesWire returns the wire bytes of es, in the order given, each entry as the object {cls, src, h,
// cid, owner} with an absent cid or owner left out. It refuses an entry whose Class is not one of the
// four, and text that a reader would refuse: text that is not valid UTF-8 (the bytes of a lone surrogate
// among them) or holds a noncharacter.
func EntriesWire(es []Entry) ([]byte, error) {
	v, err := entriesValue(es)
	if err != nil {
		return nil, fmt.Errorf("paztport influence: the influence can't be written: %w", err)
	}
	return wire("influence", v)
}

func entriesValue(es []Entry) (json.Value, error) {
	items := make([]json.Value, len(es))
	for i, e := range es {
		if !e.Class.known() {
			return json.Value{}, errors.New("entry " + strconv.Itoa(i) + " has a class that is not one of the four")
		}
		members := []json.Member{
			{Name: "cls", Value: json.S(string(e.Class))},
			{Name: "src", Value: json.S(e.Src)},
			{Name: "h", Value: json.S(e.H)},
		}
		if e.HasCID {
			members = append(members, json.Member{Name: "cid", Value: json.S(e.CID)})
		}
		if e.Owner != "" {
			members = append(members, json.Member{Name: "owner", Value: json.S(e.Owner)})
		}
		items[i] = json.Obj(members...)
	}
	return json.Arr(items...), nil
}

// readClass returns object o's member cls, refusing o unless it is a string naming one of the four
// classes.
func readClass(o json.Value) (Class, error) {
	s, err := json.String(o, "cls")
	if err != nil {
		return "", err
	}
	c, ok := ParseClass(s)
	if !ok {
		return "", errors.New(`the member "cls" is not an influence class`)
	}
	return c, nil
}

// readOwner returns object o's member owner, or "" when o has none, refusing o if it is not a non-empty
// string: an empty owner is refused, not read as "no owner", so it can never be taken for a known one.
func readOwner(o json.Value) (string, error) {
	if _, ok := json.Field(o, "owner"); !ok {
		return "", nil
	}
	s, err := json.String(o, "owner")
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New(`the member "owner" is empty`)
	}
	return s, nil
}

// parseWire reads b as the wire bytes of an object of kind what, which build makes from the value read.
func parseWire[T any](b []byte, what string, build func(json.Value) (T, error)) (T, error) {
	v, err := json.ReadWire(b)
	if err == nil {
		var t T
		if t, err = build(v); err == nil {
			return t, nil
		}
	}
	var zero T
	return zero, malformed(what, err)
}

// wire returns v's canonical bytes, the wire form of an object of kind what.
func wire(what string, v json.Value) ([]byte, error) {
	b, err := json.Wire(v)
	if err != nil {
		return nil, fmt.Errorf("paztport influence: the %s can't be written: %w", what, err)
	}
	return b, nil
}

// malformed returns the refusal of an object of kind what, for the reason err gives.
func malformed(what string, err error) error {
	return fmt.Errorf("paztport influence: malformed %s: %w", what, err)
}
