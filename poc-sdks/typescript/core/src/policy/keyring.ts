// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { sign, utf8, verify } from "../crypto/crypto.ts";
import { canonicalize } from "../encoding/jcs.ts";
import { isNotAfter } from "./validity.ts";

/** A keyring signed offline by its policy key: the policy key and the services' public keys; the new form's `notAfter` (ms since the epoch, inclusive) is when the owner stops vouching for them, and the old form, with none, verifies for recorded evidence but is never current; an own `notAfter` member alone decides the form. */
export type SignedKeyring = { policy: string; services: Record<string, string>; sig: string; notAfter?: number };

/** The bytes a keyring signature covers: domain prefix + JCS of notAfter (new form only), the policy key and services; throws on a notAfter outside [0, 2^53 − 1]. */
export function keyringSigningBytes(policy: string, services: Record<string, string>, notAfter?: number): Uint8Array {
  if (notAfter === undefined) return utf8("paztport-keyring\n" + canonicalize({ policy, services }));
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return utf8("paztport-keyring\n" + canonicalize({ notAfter, policy, services }));
}

function signForm(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string, notAfter?: number): SignedKeyring {
  const sig = encode(sign(policyPrivateKey, keyringSigningBytes(policyPublicKey, services, notAfter)));
  return notAfter === undefined ? { policy: policyPublicKey, services, sig } : { policy: policyPublicKey, services, sig, notAfter };
}

/** Signs a keyring with its policy key in the new form, vouching for it until `notAfter` (throws on one outside [0, 2^53 − 1], an absent one included); the caller must have checked that each key is that service's current key. */
export function signKeyring(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string, notAfter: number): SignedKeyring {
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return signForm(services, policyPublicKey, policyPrivateKey, notAfter);
}

/** Signs a keyring in the old form, which is never current; the caller must have checked that each key is that service's current key, as for signKeyring. It exists only for deliberate old-form cases (recorded evidence, vectors, tests). */
export function signKeyringOldForm(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string): SignedKeyring {
  return signForm(services, policyPublicKey, policyPrivateKey);
}

/** The same services and policy key, signed again in the new form until `notAfter`; the caller must still hold every listed key current, as a retired key needs a new keyring, not a renewal. */
export function renewKeyring(k: SignedKeyring, notAfter: number, policyPrivateKey: string): SignedKeyring {
  return signKeyring(k.services, k.policy, policyPrivateKey, notAfter);
}

/** True only when the keyring names `policyKey` and its signature verifies under it in the keyring's own form, a `notAfter` outside [0, 2^53 − 1] failing rather than read as absent; never throws, and says nothing about time (see isCurrent). */
export function verifyKeyring(k: SignedKeyring, policyKey: string): boolean {
  try {
    const windowed = Object.hasOwn(k, "notAfter");
    if (windowed && !isNotAfter(k.notAfter)) return false;
    return (
      k.policy === policyKey &&
      typeof k.sig === "string" &&
      verify(policyKey, keyringSigningBytes(k.policy, k.services, windowed ? k.notAfter : undefined), decode(k.sig))
    );
  } catch {
    return false;
  }
}
