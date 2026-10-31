// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  createHash,
  randomBytes as nodeRandomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import { decode, encode } from "../encoding/b64url.ts";

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

export function randomBytes(n: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(n));
}

/** False when `text` holds a surrogate that is not half of a valid pair; with the `u` flag a valid pair is one code point. */
export function isWellFormed(text: string): boolean {
  return !/\p{Surrogate}/u.test(text);
}

/** The UTF-8 bytes of `text`. Throws TypeError on a lone surrogate, which has none and would otherwise encode as U+FFFD. */
export function utf8(text: string): Uint8Array {
  if (!isWellFormed(text)) {
    throw new TypeError("not well-formed Unicode");
  }
  return new Uint8Array(Buffer.from(text, "utf8"));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  return new Uint8Array(Buffer.concat(parts));
}

/** Public key: X.509 SPKI DER; private key: PKCS#8 DER; both base64url. */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: encode(publicKey.export({ format: "der", type: "spki" })),
    privateKey: encode(privateKey.export({ format: "der", type: "pkcs8" })),
  };
}

export function sign(privateKey: string, message: Uint8Array): Uint8Array {
  const key = createPrivateKey({ key: Buffer.from(decode(privateKey)), format: "der", type: "pkcs8" });
  return new Uint8Array(nodeSign(null, message, key));
}

/** Returns false (never throws) on any failure. */
export function verify(publicKey: string, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(decode(publicKey)), format: "der", type: "spki" });
    return nodeVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

const KEY_PROBE = utf8("paztport key probe");

/** True when the private key signs a probe that the public key verifies; false (never throws) for an unusable key. */
export function keyPairMatches(privateKey: string, publicKey: string): boolean {
  try {
    return verify(publicKey, KEY_PROBE, sign(privateKey, KEY_PROBE));
  } catch {
    return false;
  }
}

/** True when `publicKey` is a base64url X.509 SPKI Ed25519 public key; false (never throws) for anything else, a non-string included. */
export function isEd25519PublicKey(publicKey: unknown): boolean {
  try {
    if (typeof publicKey !== "string") return false;
    return createPublicKey({ key: Buffer.from(decode(publicKey)), format: "der", type: "spki" }).asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}
