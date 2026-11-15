// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

// A binding is b64url(SHA-256(bytes)) over bytes that say what a hop sent, so a chain copied onto another
// payload fails. Which kind a stamp's bind must be is decided by where the stamp sits, never read from
// the binding. Every binding refuses text that is not valid UTF-8, the Go form of the spec's lone
// surrogate, rather than hash a replacement for it.

// PromptBinding returns the binding a run's origin stamp carries for its prompt:
//
//	b64url(SHA-256(utf8("prompt\n" || prompt)))
//
// It refuses a prompt that is not valid UTF-8.
func PromptBinding(prompt string) (string, error) {
	if !text.Valid(prompt) {
		return "", errors.New("paztport stamp: the prompt is not valid UTF-8")
	}
	return binding("prompt\n" + prompt), nil
}

// ResponseBinding returns the binding the last stamp of a response chain carries (wire.md, Bindings):
//
//	b64url(SHA-256(utf8(resultHash || "\n" || callID)))
//
// There is no prefix: the bytes start with the result hash, itself a hash under a prefix of its own. Over
// HTTP, callID is the request's rid. What the responder claims about its answer travels in its stamp's block,
// not in the binding.
//
// It refuses a resultHash or callID that is not valid UTF-8, and a callID holding "\n", which would let two
// pairs of hash and id share bytes.
func ResponseBinding(resultHash, callID string) (string, error) {
	switch {
	case !text.Valid(resultHash):
		return "", errors.New("paztport stamp: the result hash is not valid UTF-8")
	case !text.Valid(callID):
		return "", errors.New("paztport stamp: the call id is not valid UTF-8")
	case strings.Contains(callID, "\n"):
		return "", errors.New("paztport stamp: the call id holds a newline")
	}
	return binding(resultHash + "\n" + callID), nil
}

// binding returns b64url(SHA-256(b)).
func binding(b string) string {
	sum := sha256.Sum256([]byte(b))
	return b64.Encode(sum[:])
}
