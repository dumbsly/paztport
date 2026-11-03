// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
)

// Answer is an answer the SDK gives in place of a handler's: a refusal, or the handshake endpoint's
// reply. The adapter sends Body exactly as these bytes, with the header Content-Type: wire.ContentType
// and no parameters, so that a framework neither serialises it again nor guesses its type.
type Answer struct {
	// Status is the HTTP status.
	Status int
	// Body is the body, UTF-8 JSON text.
	Body []byte
}

// Refusal returns the refusal of a request with status and code r: the body {"reason":"<code>"}, one
// member and no whitespace, so every implementation sends the same bytes for the same code. It carries
// no suspect and no rid: who is suspected is for the operator and the responder, and the suspect is
// usually the caller itself.
//
// A code is one of the spec's, a constant of the program, never a request's text. Refusal panics if r
// is not valid UTF-8 or holds a noncharacter: no JSON text can carry such a code, and no spec code is one.
func Refusal(status int, r reason.Code) Answer {
	return Answer{Status: status, Body: codeBody("reason", string(r))}
}

// handshakeError returns the handshake endpoint's error code: 400 and the body {"error":"<code>"}. It
// answers a handshake, not a call, so it is not a refusal. Like [Refusal], it panics on a code that is
// not valid UTF-8 or holds a noncharacter.
func handshakeError(code string) Answer {
	return Answer{Status: 400, Body: codeBody("error", code)}
}

// codeBody returns the wire bytes of the object whose one member, name, is the string code.
func codeBody(name, code string) []byte {
	b, err := json.Wire(json.Obj(json.Member{Name: name, Value: json.S(code)}))
	if err != nil {
		panic("paztport http: a code that no JSON text can carry")
	}
	return b
}
