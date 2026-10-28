// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";
import { isNotAfter, readNotAfter } from "./validity.ts";

/** The policy root signed by the policy key; the new form's `notAfter` (ms since the epoch, inclusive) is when the owner stops vouching for its routes, and the old form, with none, verifies for recorded evidence but is never current; an own `notAfter` member alone decides the form. */
export type SignedRoot = { rootId: string; root: string; sig: string; notAfter?: number };

/** The bytes a root signature covers, `root` as its base64url text: new form, domain prefix + JCS of notAfter, root and rootId (throws on a notAfter outside [0, 2^53 − 1]); old form, with no notAfter, `rootId|root`. */
export function rootSigningBytes(rootId: string, root: string, notAfter?: number): Uint8Array {
  if (notAfter === undefined) return utf8(`${rootId}|${root}`);
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return utf8("paztport-root\n" + canonicalize({ notAfter, root, rootId }));
}

function signText(rootId: string, rootB64: string, policyPrivateKey: string, notAfter?: number): SignedRoot {
  const sig = encode(sign(policyPrivateKey, rootSigningBytes(rootId, rootB64, notAfter)));
  return notAfter === undefined ? { rootId, root: rootB64, sig } : { rootId, root: rootB64, sig, notAfter };
}

/** Signs `root` under `rootId` in the new form, vouching for it until `notAfter` (throws on one outside [0, 2^53 − 1], an absent one included); the caller must have checked that the tree's routes are the ones it currently allows. */
export function signRoot(root: Uint8Array, rootId: string, policyPrivateKey: string, notAfter: number): SignedRoot {
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return signText(rootId, encode(root), policyPrivateKey, notAfter);
}

/** Signs `root` under `rootId` in the old form, which is never current: only for v1 and for deliberate old-form cases (recorded evidence, vectors, tests). */
export function signRootOldForm(root: Uint8Array, rootId: string, policyPrivateKey: string): SignedRoot {
  return signText(rootId, encode(root), policyPrivateKey);
}

/** A signed root read whole from parsed JSON, its own `notAfter` kept (judged by value) and other members dropped; throws naming `what` and the field when `v` is not an object of string `rootId`, `root` and `sig`, or has a `notAfter` outside [0, 2^53 − 1]. Checks no signature. */
export function parseSignedRoot(v: unknown, what: string): SignedRoot {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new TypeError(`${what} must be an object`);
  const o = v as Record<string, unknown>;
  for (const field of ["rootId", "root", "sig"]) {
    if (typeof o[field] !== "string") throw new TypeError(`${what}.${field} must be a string`);
  }
  let notAfter: number | undefined;
  try {
    notAfter = readNotAfter(o, "notAfter");
  } catch {
    throw new TypeError(`${what}.notAfter must be an integer in [0, 2^53 - 1]`);
  }
  const sr: SignedRoot = { rootId: o.rootId as string, root: o.root as string, sig: o.sig as string };
  return notAfter === undefined ? sr : { ...sr, notAfter };
}

/** The same root text and rootId signed again in the new form until `notAfter`, naming exactly the tree `sr` did; the caller must still allow every route in it, as a narrowed policy needs a new tree, not a renewal. */
export function renewRoot(sr: SignedRoot, notAfter: number, policyPrivateKey: string): SignedRoot {
  return signText(sr.rootId, sr.root, policyPrivateKey, notAfter);
}

/** True when the signature verifies under `policyPublicKey` in the root's own form, a `notAfter` outside [0, 2^53 − 1] failing rather than read as absent; never throws, and says nothing about time (see isCurrent). */
export function verifyRoot(sr: SignedRoot, policyPublicKey: string): boolean {
  try {
    if (typeof sr.rootId !== "string" || typeof sr.root !== "string" || typeof sr.sig !== "string") return false;
    const windowed = Object.hasOwn(sr, "notAfter");
    if (windowed && !isNotAfter(sr.notAfter)) return false;
    return verify(policyPublicKey, rootSigningBytes(sr.rootId, sr.root, windowed ? sr.notAfter : undefined), decode(sr.sig));
  } catch {
    return false;
  }
}
