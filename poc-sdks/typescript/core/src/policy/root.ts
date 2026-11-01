// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, sign, utf8, verify } from "../crypto/crypto.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readFile, readToken, type JsonValue } from "../encoding/json.ts";
import { exactly, int, object, str } from "../internal/fields.ts";
import { isNotAfter } from "./validity.ts";

/** The policy root signed by the policy key; `notAfter` (ms since the epoch, inclusive) is when the owner stops vouching for its routes. */
export type SignedRoot = { rootId: string; root: string; sig: string; notAfter: number };

/** The bytes a root signature covers, `root` as its base64url text: domain prefix + JCS of notAfter, root and rootId; throws on a notAfter outside [0, 2^53 − 1]. */
export function rootSigningBytes(rootId: string, root: string, notAfter: number): Uint8Array {
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return concat(utf8("paztport-root\n"), writeWire({ notAfter, root, rootId }));
}

function signText(rootId: string, rootB64: string, policyPrivateKey: string, notAfter: number): SignedRoot {
  const sig = encode(sign(policyPrivateKey, rootSigningBytes(rootId, rootB64, notAfter)));
  return { rootId, root: rootB64, sig, notAfter };
}

/** Signs `root` under `rootId`, vouching for it until `notAfter` (throws on one outside [0, 2^53 − 1], an absent one included); the caller must have checked that the tree's routes are the ones it currently allows. */
export function signRoot(root: Uint8Array, rootId: string, policyPrivateKey: string, notAfter: number): SignedRoot {
  return signText(rootId, encode(root), policyPrivateKey, notAfter);
}

/**
 * The root's schema: exactly `notAfter`, `root`, `rootId` and `sig`. A session message's own reader applies it to the
 * root it carries.
 */
export function rootOf(value: JsonValue): SignedRoot {
  const o = object(value);
  exactly(o, ["notAfter", "root", "rootId", "sig"]);
  return { rootId: str(o, "rootId"), root: str(o, "root"), sig: str(o, "sig"), notAfter: int(o, "notAfter") };
}

/**
 * Reads `root.json` in any member order and spacing: MalformedJson for bytes that do not read, an Error naming the
 * member for a root the schema refuses. Checks no signature.
 */
export function readRootFile(bytes: Uint8Array): SignedRoot {
  return rootOf(readFile(bytes));
}

/** Reads a root from its token, by readRootFile's schema. */
export function readRoot(token: string): SignedRoot {
  return rootOf(readToken(token));
}

/** The same root text and rootId signed again until `notAfter`, naming exactly the tree `sr` did; the caller must still allow every route in it, as a narrowed policy needs a new tree, not a renewal. */
export function signRenewedRoot(sr: SignedRoot, notAfter: number, policyPrivateKey: string): SignedRoot {
  return signText(sr.rootId, sr.root, policyPrivateKey, notAfter);
}

/** True when the signature verifies under `policyPublicKey` over the root's own `notAfter`, which must be in [0, 2^53 − 1]; one that is missing (or inherited) fails. Never throws, and says nothing about time (see isCurrent). */
export function verifyRoot(sr: SignedRoot, policyPublicKey: string): boolean {
  try {
    if (typeof sr.rootId !== "string" || typeof sr.root !== "string" || typeof sr.sig !== "string") return false;
    if (!Object.hasOwn(sr, "notAfter") || !isNotAfter(sr.notAfter)) return false;
    return verify(policyPublicKey, rootSigningBytes(sr.rootId, sr.root, sr.notAfter), decode(sr.sig));
  } catch {
    return false;
  }
}
