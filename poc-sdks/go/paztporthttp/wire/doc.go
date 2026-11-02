// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package wire is how v3 travels over HTTP: the headers a request and a response carry, the request's
// binding, a response's result hash, and the caller's check of a response. It sends nothing and uses no
// HTTP library: every function takes the strings and bytes a transport already has, so it serves a
// net/http handler, a gateway's external processor or a test alike.
//
// A request carries its chain, its route's proof and its influence in the [Chain], [Proof] and
// [Influence] headers, each a token, the base64url of the value's canonical (JCS) bytes, which
// [EncodeChain], [EncodeProof] and [EncodeInfluence] write. A call between organisations names its
// session in the [Session] header, as plain text. The last stamp's bind is [Bind] of the request's
// method, target and body, the target bound exactly as sent.
//
// A response is attested by one more stamp on the request chain the answering service received, signed
// for the caller and binding the response's [ResultHash] and its content labels; [EncodeResponse] writes
// both into the [Response] header. The caller already holds the proof for the request's route, so the
// response carries none. [CheckResponse] checks the header at the caller, with the chain and proof it
// sent, and returns the labels only when the whole response verifies.
//
// A header's value is read by [HeaderValue]: only HTTP's optional whitespace around it is trimmed, and a
// value of nothing else is absent. Values that do not read are left to the verifier, which answers each
// with the spec's reason code. Nonce keys are <rid>|<last svc>|req for a request and <rid>|<target>|resp
// for a response, the target being the receiver the request was sent to.
package wire
