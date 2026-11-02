// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// cidLength is the number of random bytes in a fresh content id.
const cidLength = 16

// Label is what a server says about the content of a result it attests: its class, a content id the
// caller can later cite, and whose data it is. On the wire it is the object {cls, cid, owner}, with
// owner left out when absent. Labels travel beside a response and its binding covers them, so they can't
// be changed in transit.
type Label struct {
	// Class is the content's class.
	Class Class
	// CID is the content id.
	CID string
	// Owner is an opaque id of whose data the content is, or "" for none. The server takes it from its
	// own records of whose data it served, never from the content.
	Owner string
}

var (
	labelRequired = []string{"cid", "cls"}
	labelOptional = []string{"owner"}
)

// NewLabel returns a label for new content of class c, owned by owner ("" for none), with a fresh
// content id: 16 random bytes, as base64url.
func NewLabel(c Class, owner string) Label {
	var cid [cidLength]byte
	// crypto/rand.Read never returns an error: if the system's source fails, the program stops.
	rand.Read(cid[:])
	return Label{Class: c, CID: b64.Encode(cid[:]), Owner: owner}
}

// Entry returns the entry a caller adds to its influence for content carrying l, once the whole response
// verifies: src names the source, "server:<serverId>" or, over HTTP, "http:<target>" for the service the
// request was sent to, and h is the response's result hash or binding.
func (l Label) Entry(src, h string) Entry {
	return Entry{Class: l.Class, Src: src, H: h, CID: l.CID, HasCID: true, Owner: l.Owner}
}

// ParseLabels reads a list of labels from its wire bytes, its canonical bytes. The bytes hold an array
// whose every item is an object of exactly a label's members: cls, one of the four classes; the string
// cid; and, when present, owner, a non-empty string. The labels keep the order they were read in.
func ParseLabels(wire []byte) ([]Label, error) {
	return parseWire(wire, "labels", labelsFromValue)
}

func labelsFromValue(v json.Value) ([]Label, error) {
	if v.Kind() != json.KindArray {
		return nil, errors.New("the value is not an array")
	}
	items := v.Items()
	ls := make([]Label, len(items))
	for i, item := range items {
		l, err := labelFromValue(item)
		if err != nil {
			return nil, fmt.Errorf("label %d: %w", i, err)
		}
		ls[i] = l
	}
	return ls, nil
}

func labelFromValue(o json.Value) (Label, error) {
	if err := json.Exactly(o, labelRequired, labelOptional); err != nil {
		return Label{}, err
	}
	c, err := class(o)
	if err != nil {
		return Label{}, err
	}
	cid, err := json.String(o, "cid")
	if err != nil {
		return Label{}, err
	}
	owner, err := owner(o)
	if err != nil {
		return Label{}, err
	}
	return Label{Class: c, CID: cid, Owner: owner}, nil
}

// LabelsWire returns the wire bytes of ls, in the order given, each label as the object {cls, cid,
// owner} with an absent owner left out: the bytes a response binding commits to. It refuses a label
// whose Class is not one of the four, and text that a reader would refuse, as EntriesWire does.
func LabelsWire(ls []Label) ([]byte, error) {
	items := make([]json.Value, len(ls))
	for i, l := range ls {
		if !l.Class.known() {
			return nil, errors.New("paztport influence: the labels can't be written: label " + strconv.Itoa(i) +
				" has a class that is not one of the four")
		}
		members := []json.Member{
			{Name: "cls", Value: json.S(string(l.Class))},
			{Name: "cid", Value: json.S(l.CID)},
		}
		if l.Owner != "" {
			members = append(members, json.Member{Name: "owner", Value: json.S(l.Owner)})
		}
		items[i] = json.Obj(members...)
	}
	return wire("labels", json.Arr(items...))
}
