// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/rand"
	"encoding/hex"
)

// NewRID returns a new request id: a random UUID (RFC 9562, version 4), 122 bits from crypto/rand, in
// its lower-case text form. The spec asks an origin for at least 122 random bits, so that the edge's
// replicas never share a rid without needing to agree on anything.
func NewRID() string {
	var b [16]byte
	// Read never returns an error: it crashes the program if the system's source fails.
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant 10, RFC 9562's
	var s [36]byte
	hex.Encode(s[0:8], b[0:4])
	s[8] = '-'
	hex.Encode(s[9:13], b[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], b[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], b[8:10])
	s[23] = '-'
	hex.Encode(s[24:36], b[10:16])
	return string(s[:])
}
