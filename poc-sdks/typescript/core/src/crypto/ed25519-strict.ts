// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Rules 2 to 4 of the signature rule (spec wire.md, Signatures), checked on the bytes before the library verifies.
// RFC 8032 leaves these to the verifier, and libraries choose differently: the three SDKs carry the same checks, so
// they refuse the same bytes whatever their library accepts. spec/vectors/ed25519.json pins them.

/** 32 little-endian bytes from hex written most significant digit first, so the constants read as the numbers they are. */
function littleEndian(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex").reverse());
}

/** The group order L = 2^252 + 27742317777372353535851937790883648493. */
const L = littleEndian("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

/** The field prime p = 2^255 − 19. */
const P = littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

/**
 * The y of every point of small order, ascending: 0 (order 4), 1 (the identity), y8 and p − y8 (order 8), p − 1 (order 2).
 * Testing y alone also refuses the encodings of x = 0 that set the sign bit, which RFC 8032 decoding refuses anyway.
 */
export const SMALL_ORDER_Y: readonly Uint8Array[] = [
  littleEndian("0000000000000000000000000000000000000000000000000000000000000000"),
  littleEndian("0000000000000000000000000000000000000000000000000000000000000001"),
  littleEndian("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826"),
  littleEndian("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7"),
  littleEndian("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
];

/** True when the little-endian `a` is below the little-endian `b`, both 32 bytes. */
function below(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 31; i >= 0; i--) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.every((byte, i) => byte === b[i]);
}

/** A point's encoding is canonical and not of small order: its y, the sign bit cleared, is below p and not a small-order y. */
function strictPoint(encoding: Uint8Array): boolean {
  const y = Uint8Array.from(encoding);
  y[31] &= 0x7f;
  return below(y, P) && !SMALL_ORDER_Y.some((small) => same(y, small));
}

/** Rules 2 to 4 for the key `a` (32 bytes) and `signature` (64 bytes): S below L, then R and A canonical and not of small order. */
export function strictEncodings(a: Uint8Array, signature: Uint8Array): boolean {
  if (a.length !== 32 || signature.length !== 64) return false;
  return below(signature.subarray(32), L) && strictPoint(signature.subarray(0, 32)) && strictPoint(a);
}
