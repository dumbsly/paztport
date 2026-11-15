// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package wire is how version 4 travels over HTTP (wire.md, HTTP): the headers a request and a response carry,
// the request's binding, a response's result hash, the nonce keys, and the caller's check of a response. It
// sends nothing and uses no HTTP library: every function takes the strings and bytes a transport already has,
// so it serves a net/http handler, a gateway's external processor or a test alike.
//
// A request carries its chain, its route's proof and its blocks, one per stamp, in the [Chain], [Proof] and
// [Extensions] headers, each a token, the base64url of the value's canonical (JCS) bytes, which [EncodeChain],
// [EncodeProof] and [EncodeBlocks] write. A call between organisations names its session in the [Session]
// header, as plain text. The last stamp's bind is [Bind] of the request's method, target and body, the target
// bound exactly as sent.
//
// A response is attested by one more stamp on the request chain the answering service received, signed for
// the caller, binding the response's [ResultHash] and the request's rid, and committing to the response's own
// block; [EncodeResponse] writes the stamp and the block into the [Response] header. The caller already holds
// the proof for the request's route and the blocks it sent, so the response carries neither. [CheckResponse]
// checks the header at the caller, with the chain, blocks and proof it sent, and [ResponseCheck.Response] hands
// out what the response's block holds for an extension only when the whole response verifies.
//
// A header's value is read by [HeaderValue]: only HTTP's optional whitespace around it is trimmed, and a
// value of nothing else is absent. Values that do not read are left to the verifier, which answers each
// with the spec's reason code. Nonce keys are the JCS text of an array of strings (verification.md, Freshness
// and replay), [RequestNonceKey] and [ResponseNonceKey]: [rid, last svc, last rcv, "req"] for a request and
// [rid, last rcv, "resp"] for a response, last rcv being the receiver the request chain's last stamp names,
// with the operation when it names one. Where that operation declares a key, the key value comes before the
// direction: [rid, last svc, last rcv, key, "req"] and [rid, last rcv, key, "resp"].
package wire
