// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// EncodeChain returns the value of a request's [Chain] header: c's token. It refuses what
// stamp.Chain.Token refuses, an empty chain among them.
func EncodeChain(c stamp.Chain) (string, error) {
	return c.Token()
}

// EncodeProof returns the value of a request's [Proof] header: p's token. It refuses what
// policy.Proof.Token refuses.
func EncodeProof(p policy.Proof) (string, error) {
	return p.Token()
}

// EncodeInfluence returns the value of a request's [Influence] header: the token of es, in the order
// given, which is the list the last stamp's infl commits to. With no entries it returns "", and the
// request carries no header, which a receiver reads as none; a token is never "". It refuses what
// influence.EntriesWire refuses.
func EncodeInfluence(es []influence.Entry) (string, error) {
	if len(es) == 0 {
		return "", nil
	}
	b, err := influence.EntriesWire(es)
	if err != nil {
		return "", err
	}
	return b64.Encode(b), nil
}

// EncodeResponse returns the value of a response's [Response] header: the token of the object {labels,
// stamp}, with exactly those members, s the response stamp and labels in the order its binding covers
// them. No labels are written as []. It refuses a stamp that stamp.Stamp.Wire refuses, labels that
// influence.LabelsWire refuses, and an object over the wire limit.
func EncodeResponse(s stamp.Stamp, labels []influence.Label) (string, error) {
	unwritable := func(err error) error {
		return fmt.Errorf("paztport wire: the response header can't be written: %w", err)
	}
	sb, err := s.Wire()
	if err != nil {
		return "", err
	}
	lb, err := influence.LabelsWire(labels)
	if err != nil {
		return "", err
	}
	sv, err := json.ReadWire(sb)
	if err != nil {
		return "", unwritable(err)
	}
	lv, err := json.ReadWire(lb)
	if err != nil {
		return "", unwritable(err)
	}
	tok, err := json.Token(json.Obj(
		json.Member{Name: "labels", Value: lv},
		json.Member{Name: "stamp", Value: sv},
	))
	if err != nil {
		return "", unwritable(err)
	}
	return tok, nil
}
