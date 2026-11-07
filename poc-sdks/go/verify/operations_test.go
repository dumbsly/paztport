// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// opRoute is the one route the operation fixture's policy allows.
const opRoute = "gateway/orders#createOrder/payment#charge"

// leaf is a single-leaf tree's proof of route: the leaf is the root, so there are no siblings, and the root
// bytes.
func leaf(t *testing.T, route string) (policy.Proof, []byte) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	root, err := policy.LeafHash(salt, route)
	if err != nil {
		t.Fatal(err)
	}
	return policy.Proof{LeafSalt: salt, RootID: "ops"}, root
}

// operations returns the mesh fixture with the gateway naming gatewayRcv, and the proof it sends proving
// proofRoute, against a policy that allows only opRoute.
func operations(t *testing.T, gatewayRcv, proofRoute string) *setup {
	t.Helper()
	s := mesh(t)
	_, root := leaf(t, opRoute)
	p, _ := leaf(t, proofRoute)
	tok, err := p.Token()
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.Roots = []verify.PinnedRoot{{Root: root, RootID: "ops", NotAfter: 4102444800000}}
	s.stamps = []stamp.Stamp{
		{Svc: "gateway", Inst: "gw-1", RID: "rid-1", TS: now - 1500, Rcv: gatewayRcv, Bind: "bind-0"},
		{Svc: "orders", Inst: "ord-1", RID: "rid-1", TS: now - 500, Rcv: "payment#charge", Bind: "bind-1"},
	}
	s.in.Receiver = "payment#charge"
	s.in.Proof = &tok
	return s
}

func TestOperationNamedInRcvVerifies(t *testing.T) {
	s := operations(t, "orders#createOrder", opRoute)
	if got := s.run(t); got.Reason != reason.OK {
		t.Fatalf("Verify = %+v, want OK", got)
	}
}

// TestAnotherOperationIsBindingMismatch refuses a receiver that is not the last rcv, and shows that the
// refusal spends no nonce: the same chain for the right receiver then verifies.
func TestAnotherOperationIsBindingMismatch(t *testing.T) {
	s := operations(t, "orders#createOrder", opRoute)
	v := verify.New(s.cfg)
	chain := ptr(s.token(t))
	in := s.in
	in.Chain = chain
	in.Receiver = "payment#refund"
	if got, err := v.Verify(t.Context(), in); err != nil || got.Reason != reason.BindingMismatch {
		t.Fatalf("Verify = %+v, %v, want BINDING_MISMATCH", got, err)
	}
	in.Receiver = "payment#charge"
	if got, err := v.Verify(t.Context(), in); err != nil || got.Reason != reason.OK {
		t.Fatalf("Verify = %+v, %v, want OK", got, err)
	}
}

func TestInnerRcvNamingAnotherServiceFails(t *testing.T) {
	s := operations(t, "search#find", opRoute)
	if got := s.run(t); got.Reason != reason.BindingMismatch {
		t.Fatalf("Verify = %+v, want BINDING_MISMATCH", got)
	}
}

func TestEmptyOperationFails(t *testing.T) {
	s := operations(t, "orders#", opRoute)
	if got := s.run(t); got.Reason != reason.BindingMismatch {
		t.Fatalf("Verify = %+v, want BINDING_MISMATCH", got)
	}
}

func TestProofForAnotherOperationsRouteFails(t *testing.T) {
	s := operations(t, "orders#getOrder", opRoute)
	if got := s.run(t); got.Reason != reason.PathNotAllowed {
		t.Fatalf("Verify = %+v, want PATH_NOT_ALLOWED", got)
	}
}
