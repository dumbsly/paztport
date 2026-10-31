// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { sign, utf8, verify } from "../crypto/crypto.ts";
import { canonicalize } from "../encoding/jcs.ts";
import { isNotAfter } from "./validity.ts";

/** A keyring signed offline by its policy key: the policy key and the services' public keys; `notAfter` (ms since the epoch, inclusive) is when the owner stops vouching for them. */
export type SignedKeyring = { policy: string; services: Record<string, string>; sig: string; notAfter: number };

/** The bytes a keyring signature covers: domain prefix + JCS of notAfter, the policy key and services; throws on a notAfter outside [0, 2^53 − 1]. */
export function keyringSigningBytes(policy: string, services: Record<string, string>, notAfter: number): Uint8Array {
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return utf8("paztport-keyring\n" + canonicalize({ notAfter, policy, services }));
}

/** Signs a keyring with its policy key, vouching for it until `notAfter` (throws on one outside [0, 2^53 − 1], an absent one included); the caller must have checked that each key is that service's current key. */
export function signKeyring(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string, notAfter: number): SignedKeyring {
  const sig = encode(sign(policyPrivateKey, keyringSigningBytes(policyPublicKey, services, notAfter)));
  return { policy: policyPublicKey, services, sig, notAfter };
}

/** True only when the keyring names `policyKey` and its signature verifies under it over the keyring's own `notAfter`, which must be in [0, 2^53 − 1]; one that is missing (or inherited) fails. Never throws, and says nothing about time (see isCurrent). */
export function verifyKeyring(k: SignedKeyring, policyKey: string): boolean {
  try {
    if (!Object.hasOwn(k, "notAfter") || !isNotAfter(k.notAfter)) return false;
    return (
      k.policy === policyKey &&
      typeof k.sig === "string" &&
      verify(policyKey, keyringSigningBytes(k.policy, k.services, k.notAfter), decode(k.sig))
    );
  } catch {
    return false;
  }
}
