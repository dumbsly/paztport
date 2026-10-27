// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";

/** A keyring signed offline by its policy key: the policy key and the services' public keys. */
export type SignedKeyring = { policy: string; services: Record<string, string>; sig: string };

/** The bytes a keyring signature covers: domain prefix + JCS of the policy key and services. */
export function keyringSigningBytes(policy: string, services: Record<string, string>): Uint8Array {
  return utf8("paztport-keyring\n" + canonicalize({ policy, services }));
}

/** Signs a keyring with its policy key, over keyringSigningBytes. */
export function signKeyring(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string): SignedKeyring {
  return { policy: policyPublicKey, services, sig: encode(sign(policyPrivateKey, keyringSigningBytes(policyPublicKey, services))) };
}

/** True only when the keyring names `policyKey` and its signature verifies under it; never throws. */
export function verifyKeyring(k: SignedKeyring, policyKey: string): boolean {
  try {
    return k.policy === policyKey && typeof k.sig === "string" && verify(policyKey, keyringSigningBytes(k.policy, k.services), decode(k.sig));
  } catch {
    return false;
  }
}
