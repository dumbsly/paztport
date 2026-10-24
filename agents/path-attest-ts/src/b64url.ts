// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

const VALID = /^[A-Za-z0-9_-]*={0,2}$/;

/** Base64url without padding. */
export function encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Strict-alphabet base64url decode; trailing padding is tolerated like Java's decoder. */
export function decode(text: string): Uint8Array {
  if (!VALID.test(text)) {
    throw new Error("invalid base64url");
  }
  const body = text.replace(/=+$/, "");
  if (body.length % 4 === 1) {
    throw new Error("invalid base64url length");
  }
  return new Uint8Array(Buffer.from(body, "base64url"));
}
