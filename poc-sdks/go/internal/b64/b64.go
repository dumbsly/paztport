// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package b64

import (
	"encoding/base64"
	"errors"
)

var (
	errAlphabet   = errors.New("base64url: a character outside the url-safe alphabet")
	errLength     = errors.New("base64url: a length one more than a multiple of 4")
	errUnusedBits = errors.New("base64url: non-zero unused bits")
)

// Encode returns the canonical base64url text of b: the url-safe alphabet, no padding.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode returns the bytes s encodes, refusing any text but the canonical one: a character outside
// A–Z, a–z, 0–9, '-' and '_' (padding and whitespace among them), a length one more than a multiple of 4,
// or a last character whose bits past the last whole byte are not zero. Its errors never quote s.
func Decode(s string) ([]byte, error) {
	// Checked before decoding: the standard library's decoder skips CR and LF.
	for i := range len(s) {
		if value(s[i]) < 0 {
			return nil, errAlphabet
		}
	}
	// The last character of a short group holds 2 (two characters) or 4 (three) bits past the last byte.
	switch len(s) % 4 {
	case 1:
		return nil, errLength
	case 2:
		if value(s[len(s)-1])&0x0f != 0 {
			return nil, errUnusedBits
		}
	case 3:
		if value(s[len(s)-1])&0x03 != 0 {
			return nil, errUnusedBits
		}
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// value returns the 6-bit value of base64url character c, or -1 when c is not one.
func value(c byte) int {
	switch {
	case 'A' <= c && c <= 'Z':
		return int(c - 'A')
	case 'a' <= c && c <= 'z':
		return int(c-'a') + 26
	case '0' <= c && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	}
	return -1
}
