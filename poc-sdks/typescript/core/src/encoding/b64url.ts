// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

const VALID = /^[A-Za-z0-9_-]*$/;

/** Base64url without padding. */
export function encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Decodes the one canonical encoding of RFC 4648 §3.5: no padding, zero in the unused bits of the last character. */
export function decode(text: string): Uint8Array {
  if (!VALID.test(text)) {
    throw new Error("invalid base64url");
  }
  if (text.length % 4 === 1) {
    throw new Error("invalid base64url length");
  }
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  if (encode(bytes) !== text) {
    throw new Error("non-zero unused bits in base64url");
  }
  return bytes;
}
