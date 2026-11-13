// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package keys

// Rules 2 to 4 of the signature rule (spec wire.md, Signatures), checked on the bytes before the library
// verifies. Rules 2 and 3 are RFC 8032's own, though not every library makes them, and the RFC leaves refusing a
// point of small order to the verifier. The three SDKs make the same checks whatever their library already
// refuses, so on these bytes their answers do not depend on the library. spec/vectors/ed25519.json pins them.

// leBytes is 32 little-endian bytes, the order an Ed25519 encoding and its scalar are written in.
type leBytes [32]byte

// littleEndian returns, as 32 little-endian bytes, the number that hex writes most significant digit first, so
// the constants below read as the numbers they are.
func littleEndian(hex string) leBytes {
	var out leBytes
	for i := range out {
		out[31-i] = hexByte(hex[2*i])<<4 | hexByte(hex[2*i+1])
	}
	return out
}

func hexByte(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// groupOrder is L = 2^252 + 27742317777372353535851937790883648493.
var groupOrder = littleEndian("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")

// fieldPrime is p = 2^255 − 19.
var fieldPrime = littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")

// smallOrderY holds the y of every point of small order, ascending: 0 (order 4), 1 (the identity), y8 and
// p − y8 (order 8), p − 1 (order 2). Testing y alone also refuses the encodings of x = 0 that set the sign
// bit, which RFC 8032 decoding refuses anyway.
var smallOrderY = [...]leBytes{
	littleEndian("0000000000000000000000000000000000000000000000000000000000000000"),
	littleEndian("0000000000000000000000000000000000000000000000000000000000000001"),
	littleEndian("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826"),
	littleEndian("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7"),
	littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
}

// below reports whether the little-endian a is below the little-endian b.
func below(a, b *leBytes) bool {
	for i := 31; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// strictPoint reports whether the 32-byte encoding is canonical and not of small order: its y, the sign bit
// cleared on a copy so the caller's bytes are left as they are, is below p and not a small-order y.
func strictPoint(encoding []byte) bool {
	var y leBytes
	copy(y[:], encoding)
	y[31] &= 0x7f
	if !below(&y, &fieldPrime) {
		return false
	}
	for i := range smallOrderY {
		if y == smallOrderY[i] {
			return false
		}
	}
	return true
}

// strictEncodings reports rules 2 to 4 for the key pub (32 bytes) and sig (64 bytes): S below L, then R and
// A canonical and not of small order. Any other length is false.
func strictEncodings(pub, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	var s leBytes
	copy(s[:], sig[32:]) // S is compared as it arrives, its top bits included
	return below(&s, &groupOrder) && strictPoint(sig[:32]) && strictPoint(pub)
}
