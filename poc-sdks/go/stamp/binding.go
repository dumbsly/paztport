// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
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

// ResponseBinding returns the binding the last stamp of a response chain carries:
//
//	b64url(SHA-256(utf8(resultHash || "\n" || callID || "\n" || JCS(labels))))
//
// with labels in the order given, each written as influence.LabelsWire writes it. There is no prefix:
// the bytes start with the result hash, itself a hash under a prefix of its own. Over HTTP, callID is
// the request's rid.
//
// It refuses a resultHash or callID that is not valid UTF-8, a callID holding "\n", which would let two
// pairs of hash and id share bytes, and labels that influence.LabelsWire refuses.
func ResponseBinding(resultHash, callID string, labels []influence.Label) (string, error) {
	switch {
	case !text.Valid(resultHash):
		return "", errors.New("paztport stamp: the result hash is not valid UTF-8")
	case !text.Valid(callID):
		return "", errors.New("paztport stamp: the call id is not valid UTF-8")
	case strings.Contains(callID, "\n"):
		return "", errors.New("paztport stamp: the call id holds a newline")
	}
	ls, err := influence.LabelsWire(labels)
	if err != nil {
		return "", fmt.Errorf("paztport stamp: no response binding: %w", err)
	}
	return binding(resultHash + "\n" + callID + "\n" + string(ls)), nil
}

// binding returns b64url(SHA-256(b)).
func binding(b string) string {
	sum := sha256.Sum256([]byte(b))
	return b64.Encode(sum[:])
}
