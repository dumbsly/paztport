// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";
import { isNotAfter } from "./validity.ts";

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

/** Signs `root` under `rootId`, in the new form until `notAfter` when it is given, else the old form; the caller must have checked that the tree's routes are the ones it currently allows. */
export function signRoot(root: Uint8Array, rootId: string, policyPrivateKey: string, notAfter?: number): SignedRoot {
  return signText(rootId, encode(root), policyPrivateKey, notAfter);
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
