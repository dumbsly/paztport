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
import { strictEncodings } from "./ed25519-strict.ts";

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

/** The X.509 SPKI DER that wraps a 32-byte Ed25519 key: the only key form the signature rule accepts. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_KEY_BYTES = 32;

/**
 * The bytes `publicKey` decodes to when they are exactly the Ed25519 SPKI, the prefix and then a 32-byte key (rule 1
 * of the signature rule); null for anything else, text that is not base64url included.
 */
function ed25519Spki(publicKey: string): Buffer | null {
  let spki: Buffer;
  try {
    spki = Buffer.from(decode(publicKey));
  } catch {
    return null;
  }
  const prefix = ED25519_SPKI_PREFIX.length;
  return spki.length === prefix + ED25519_KEY_BYTES && spki.subarray(0, prefix).equals(ED25519_SPKI_PREFIX) ? spki : null;
}

/**
 * The signature rule (spec wire.md, Signatures): the key is an Ed25519 SPKI and the encodings pass strictEncodings,
 * then the library checks the equation. Returns false (never throws) on any failure.
 */
export function verify(publicKey: string, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    const spki = ed25519Spki(publicKey);
    if (spki === null || !strictEncodings(spki.subarray(ED25519_SPKI_PREFIX.length), signature)) return false;
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
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

/**
 * True when `publicKey` is the base64url of exactly the 44-byte Ed25519 SPKI, the only key form verify accepts; false
 * (never throws) for anything else, a non-string included. A key of small order passes, as it does in the Java and Go
 * SDKs, though no signature verifies under it.
 */
export function isEd25519PublicKey(publicKey: unknown): boolean {
  return typeof publicKey === "string" && ed25519Spki(publicKey) !== null;
}
