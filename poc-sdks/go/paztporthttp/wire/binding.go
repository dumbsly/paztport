// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

// Bind returns the binding an HTTP request's last stamp carries:
//
//	b64url(SHA-256(utf8(method) || "\n" || utf8(target) || "\n" || body))
//
// target is the request target exactly as sent: the raw path, then "?" and the raw query when the query
// is not empty, with nothing decoded, re-encoded or normalised. So a bare trailing "?", which ends an
// empty query, is left out ("/pay?" binds as "/pay"), and everything else is bound as given. A caller
// passes the target it sends, and a receiver the one it received, never one rebuilt from a parsed URL.
// The body is bound as raw bytes.
//
// Bind refuses a method or target that is not valid UTF-8, the Go form of text with no UTF-8 form, such
// as one holding a lone surrogate: the request has no binding, and a receiver answers it
// BINDING_MISMATCH.
func Bind(method, target string, body []byte) (string, error) {
	switch {
	case !text.Valid(method):
		return "", errors.New("paztport wire: no request binding: the method is not valid UTF-8")
	case !text.Valid(target):
		return "", errors.New("paztport wire: no request binding: the target is not valid UTF-8")
	}
	if i := strings.IndexByte(target, '?'); i == len(target)-1 {
		target = target[:i]
	}
	h := sha256.New()
	h.Write([]byte(method + "\n" + target + "\n"))
	h.Write(body)
	return b64.Encode(h.Sum(nil)), nil
}

// ResultHash returns an HTTP response's result hash, what its attestation binds:
//
//	b64url(SHA-256(utf8("http-response\n" || status || "\n") || body))
//
// with status in decimal and the body as raw bytes, so a response can't pass under another status.
func ResultHash(status int, body []byte) string {
	h := sha256.New()
	h.Write([]byte("http-response\n" + strconv.Itoa(status) + "\n"))
	h.Write(body)
	return b64.Encode(h.Sum(nil))
}
