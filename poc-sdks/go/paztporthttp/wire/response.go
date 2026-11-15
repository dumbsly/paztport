// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// attestationMembers are the members of a response header's object: both required, and no other allowed.
var attestationMembers = []string{"block", "stamp"}

// ResponseCheck is what a caller learns from a response.
type ResponseCheck struct {
	// Result is the verdict on the response's attestation. It is OK only when the whole response verified, and
	// on OK its HandOver holds, for each extension the caller acts on, one entry per stamp sent, then the
	// response stamp's.
	Result verify.Result
	// ResultHash is the response's [ResultHash], whatever the verdict, so that a caller can record an
	// unattested response by it.
	ResultHash string
}

// Response returns the response stamp's own entry under name, the last of the hand-over's: nil unless Result is
// OK and the caller acts on name. What a response's block holds counts only when the whole response verifies.
func (rc ResponseCheck) Response(name string) *verify.StampItems {
	// A verifier hands over on OK and only then; a ResponseCheck built by hand may still hold neither.
	if !rc.Result.OK() || rc.Result.HandOver == nil {
		return nil
	}
	entries, ok := rc.Result.HandOver.Under(name)
	if !ok || len(entries) == 0 {
		return nil
	}
	return &entries[len(entries)-1]
}

// CheckResponse checks a response's [Response] header, at the caller that sent the request (verification.md, A
// response, at the caller). sent is the chain the caller sent, sentBlocks the blocks it sent with it, one per
// stamp of sent, and sentProof the proof it sent, nil for none; header is the response header's value, "" when
// absent; status and body are the response's; caller is the caller's own name; key is the call's key value, ""
// for none: the one [policy.OperationTable.KeyValue] read from the target sent when the call named an operation
// that declares a key (the parent package's Outbound.Key). In order:
//
//  1. CHAIN_MISSING, unless sent has a stamp and the header, without its optional whitespace (see
//     [HeaderValue]), reads from its token as an object of exactly block and stamp, whose block reads as a block
//     ([stamp.ParseBlock]);
//  2. BINDING_MISMATCH, unless the response binding (stamp.ResponseBinding) of the [ResultHash] of status and
//     body and the rid of sent's origin as the call id can be computed, and so can the nonce key;
//  3. the live order, run by v on the chain sent then the response stamp, with the blocks sent then the
//     response's block, as received by caller, with the proof sent, no peer, that binding as the one expected
//     and the nonce key [ResponseNonceKey] of the rid, sent's last rcv whole, with the operation when it names
//     one, and key, so that a call is made once per request tree for each item of a keyed operation. The route
//     is the request's own, so the proof the caller sent proves it, and the response stamp must be by the
//     service that rcv names, signed for the caller. The verifier's own settings decide checks 9b and 9c, and
//     which extensions the hand-over holds.
//
// The response stamp is read only by the verifier, so its live order answers for it, from its policy check
// on. A sent chain that has no wire form, so that no request carried it, reaches the verifier as no chain, and
// a proof with no wire form as no proof; blocks that together pass the wire limit do not read, which check 9a
// answers EXTENSION_MISMATCH.
//
// CheckResponse never panics on any header, status or body, and leaves sent and sentBlocks as they were. It
// panics when sentBlocks is not one block per stamp of sent: a program fault, since the caller holds both. The
// error is the nonce cache's, when it could not answer, ctx's cancellation or deadline included; ctx reaches only
// the cache, and the check then is not OK. v must not be nil.
func CheckResponse(ctx context.Context, v *verify.Verifier, sent stamp.Chain, sentBlocks stamp.Blocks,
	sentProof *policy.Proof, header string, status int, body []byte, caller, key string) (ResponseCheck, error) {
	if len(sentBlocks) != len(sent) {
		panic(fmt.Sprintf("paztport wire: a response checked against %d stamps sent and %d blocks", len(sent),
			len(sentBlocks)))
	}
	hash := ResultHash(status, body)
	refused := func(code reason.Code) (ResponseCheck, error) {
		return ResponseCheck{Result: verify.Result{Reason: code}, ResultHash: hash}, nil
	}
	if len(sent) == 0 {
		return refused(reason.ChainMissing)
	}
	block, resp, ok := readAttestation(header)
	if !ok {
		return refused(reason.ChainMissing)
	}
	rid := sent[0].RID
	bind, err := stamp.ResponseBinding(hash, rid)
	if err != nil {
		return refused(reason.BindingMismatch)
	}
	// A part with no UTF-8 form has no text to key, as the binding has none. The rid has passed the binding, so
	// only a last rcv or key value no request could have carried reaches this.
	nonceKey, err := responseNonceKey(rid, sent[len(sent)-1].Rcv, key)
	if err != nil {
		return refused(reason.BindingMismatch)
	}
	in := verify.Input{
		Chain:           responseChain(sent, resp),
		Blocks:          responseBlocks(sentBlocks, block),
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

// readAttestation reads a response header (wire.md, HTTP): the block and the stamp, unread, of an object of
// exactly block and stamp, from its token, whose block reads as a block. It reports false for a header that is
// absent or does not read as that.
func readAttestation(header string) (stamp.Block, json.Value, bool) {
	tok, present := HeaderValue(header)
	if !present {
		return stamp.Block{}, json.Value{}, false
	}
	o, err := json.ReadToken(tok)
	if err != nil || json.Exactly(o, attestationMembers, nil) != nil {
		return stamp.Block{}, json.Value{}, false
	}
	bv, _ := json.Field(o, "block")
	// The token read as canonical bytes, so the member's own text is canonical too, and the block reader sees
	// exactly the bytes the response stamp's ext commits to.
	text, err := json.Wire(bv)
	if err != nil {
		return stamp.Block{}, json.Value{}, false
	}
	block, err := stamp.ParseBlock(text)
	if err != nil {
		return stamp.Block{}, json.Value{}, false
	}
	resp, _ := json.Field(o, "stamp")
	return block, resp, true
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

// responseBlocks returns the token of the blocks a response is checked with: those sent, then the response's
// own. Each block's text is its JCS text, so joined in an array they are the array's JCS text. Past the wire
// limit the token is still written, for the verifier to refuse at check 9a, as a request carrying it would be.
func responseBlocks(sent stamp.Blocks, resp stamp.Block) *string {
	texts := make([][]byte, 0, len(sent)+1)
	for _, b := range sent {
		texts = append(texts, b.Wire())
	}
	texts = append(texts, resp.Wire())
	tok := b64.Encode(slices.Concat([]byte("["), bytes.Join(texts, []byte(",")), []byte("]")))
	return &tok
}
