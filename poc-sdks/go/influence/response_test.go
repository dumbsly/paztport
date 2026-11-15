// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestResponseEntries is the HTTP rule: a response that verifies and names influence with only labels adds one
// entry per label; every other response adds exactly one local-untrusted entry. Every entry has the caller's src
// and the result hash as h.
func TestResponseEntries(t *testing.T) {
	untrusted := []influence.Entry{{Class: influence.LocalUntrusted, Src: "http:orders", H: "rh"}}
	for _, c := range []struct {
		name     string
		code     reason.Code
		response *verify.StampItems
		want     []influence.Entry
	}{
		{"a label", reason.OK,
			&verify.StampItems{Svc: "orders", Named: true, Items: []string{aLabel}},
			[]influence.Entry{{Class: influence.Private, Src: "http:orders", H: "rh", CID: "cid-1", HasCID: true,
				Owner: "alice"}}},
		{"two labels, in the order given", reason.OK,
			&verify.StampItems{Svc: "orders", Named: true, Items: []string{`{"cid":"c","cls":"public"}`, aLabel}},
			[]influence.Entry{
				{Class: influence.Public, Src: "http:orders", H: "rh", CID: "c", HasCID: true},
				{Class: influence.Private, Src: "http:orders", H: "rh", CID: "cid-1", HasCID: true, Owner: "alice"},
			}},
		{"naming influence with no label", reason.OK,
			&verify.StampItems{Svc: "orders", Named: true, Items: []string{}}, []influence.Entry{}},
		{"silent", reason.OK, &verify.StampItems{Svc: "orders"}, untrusted},
		{"a label and an entry", reason.OK,
			&verify.StampItems{Svc: "orders", Named: true,
				Items: []string{`{"cid":"c","cls":"public"}`, `{"cls":"public","h":"x","src":"s"}`}},
			untrusted},
		{"refused at check 9c", reason.ExtensionRequired,
			&verify.StampItems{Svc: "orders", Named: true, Items: []string{}}, untrusted},
		{"refused at check 9c, a label", reason.ExtensionRequired,
			&verify.StampItems{Svc: "orders", Named: true, Items: []string{aLabel}}, untrusted},
		{"a signature that fails", reason.BadSignature, nil, untrusted},
		{"no check ran", "", nil, untrusted},
		{"verified, no response stamp", reason.OK, nil, untrusted},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := influence.ResponseEntries(c.code, c.response, "http:orders", "rh")
			if !slices.Equal(got, c.want) {
				t.Fatalf("ResponseEntries = %+v, want %+v", got, c.want)
			}
		})
	}
}
