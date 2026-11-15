// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"context"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// attestationMembers are the members of a response header's object: both required, and no other allowed.
var attestationMembers = []string{"labels", "stamp"}

// ResponseCheck is what a caller learns from a response.
type ResponseCheck struct {
	// Result is the verdict on the response's attestation. It is OK only when the whole response
	// verified.
	Result verify.Result
	// Labels is always nil: a header whose labels are not empty does not read.
	// Plan 4b: the response stamp's block, handed over, replaces Labels.
	Labels []influence.Label
	// ResultHash is the response's [ResultHash], whatever the verdict, so that a caller can record an
	// unattested response by it.
	ResultHash string
}

// CheckResponse checks a response's [Response] header, at the caller that sent the request. sent is the
// chain the caller sent and sentProof the proof it sent with it, nil for none; header is the response
// header's value, "" when absent; status and body are the response's; caller is the caller's own name; key
// is the call's key value, "" for none: the one [policy.OperationTable.KeyValue] read from the target sent
// when the call named an operation that declares a key (the parent package's Outbound.Key). In order:
//
//  1. CHAIN_MISSING, unless sent has a stamp and the header, without its optional whitespace (see
//     [HeaderValue]), reads from its token as an object of exactly labels and stamp, whose labels are
//     the empty array: a label is never believed;
//  2. BINDING_MISMATCH, unless the response binding (stamp.ResponseBinding) of the [ResultHash] of status
//     and body and the rid of sent's origin as the call id can be computed;
//  3. the live order, run by v on the chain sent then the response stamp, as received by caller, with no
//     blocks token, so one empty block per stamp, the proof sent, no peer, that binding as the one expected and
//     the nonce key
//     <rid>|<last rcv>|resp, where last rcv is sent's last rcv whole, with the operation when it names
//     one, or <rid>|<last rcv>|<key>|resp when key is not empty, so that a call is made once per request
//     tree for each item of a keyed operation. The route is the request's own, so the proof the caller
//     sent proves it, and the response stamp must be by the service that rcv names, signed for the caller.
//
// The response stamp is read only by the verifier, so its live order answers for it, from its policy
// check on, and its block is the empty one: no blocks token is sent to the verifier, so a response stamp whose
// ext is not "" is EXTENSION_MISMATCH. A sent chain that has no wire form, so that no request carried it,
// reaches the verifier as no chain, and a proof with no wire form as no proof.
//
// CheckResponse never panics on any header,
// status or body, and leaves sent as it was. The error is the nonce cache's, when it could not answer,
// ctx's cancellation or deadline included; ctx reaches only the cache, and the check then is not OK. v
// must not be nil.
func CheckResponse(ctx context.Context, v *verify.Verifier, sent stamp.Chain, sentProof *policy.Proof, header string,
	status int, body []byte, caller, key string) (ResponseCheck, error) {
	hash := ResultHash(status, body)
	refused := func(code reason.Code) (ResponseCheck, error) {
		return ResponseCheck{Result: verify.Result{Reason: code}, ResultHash: hash}, nil
	}
	if len(sent) == 0 {
		return refused(reason.ChainMissing)
	}
	resp, ok := readAttestation(header)
	if !ok {
		return refused(reason.ChainMissing)
	}
	rid := sent[0].RID
	bind, err := stamp.ResponseBinding(hash, rid)
	if err != nil {
		return refused(reason.BindingMismatch)
	}
	nonceKey := rid + "|" + sent[len(sent)-1].Rcv + "|resp"
	if key != "" {
		nonceKey = rid + "|" + sent[len(sent)-1].Rcv + "|" + key + "|resp"
	}
	in := verify.Input{
		Chain:           responseChain(sent, resp),
		ExpectedBind:    &bind,
		Receiver:        caller,
		ReceiverInRoute: false,
		NonceKey:        &nonceKey,
	}
	if sentProof != nil {
		if tok, err := sentProof.Token(); err == nil {
			in.Proof = &tok
		}
	}
	result, err := v.Verify(ctx, in)
	if err != nil {
		return ResponseCheck{ResultHash: hash}, err
	}
	return ResponseCheck{Result: result, ResultHash: hash}, nil
}

// readAttestation reads a response header: the stamp, unread, of an object of exactly labels and stamp, from its
// token, whose labels are the empty array. It reports false for a header that is absent or does not read as
// that.
func readAttestation(header string) (json.Value, bool) {
	tok, present := HeaderValue(header)
	if !present {
		return json.Value{}, false
	}
	o, err := json.ReadToken(tok)
	if err != nil || json.Exactly(o, attestationMembers, nil) != nil {
		return json.Value{}, false
	}
	lv, _ := json.Field(o, "labels")
	resp, _ := json.Field(o, "stamp")
	// Plan 4b: the header becomes {block, stamp}; until then a label, which no binding covers, is refused.
	if lv.Kind() != json.KindArray || len(lv.Items()) != 0 {
		return json.Value{}, false
	}
	return resp, true
}

// responseChain returns the token of the chain a response is checked on: the stamps of sent, then resp
// as the header held it. It returns nil, no chain, when sent has no wire form or the chain is over the
// wire limit; the verifier then answers CHAIN_MISSING, after its policy check.
func responseChain(sent stamp.Chain, resp json.Value) *string {
	sb, err := sent.Wire()
	if err != nil {
		return nil
	}
	sv, err := json.ReadWire(sb)
	if err != nil {
		return nil
	}
	tok, err := json.Token(json.Arr(slices.Concat(sv.Items(), []json.Value{resp})...))
	if err != nil {
		return nil
	}
	return &tok
}
